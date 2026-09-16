#include "koios/ota.h"
#include "koios/cloudlink.h"

#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_net.h"
#include "koios/port/kp_http.h"
#include "koios/port/kp_ota.h"

#include <cJSON.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char* TAG = "koios_ota";

#define DEFAULT_ENDPOINT_URL "https://ota.api.koios.sh"

#define CHECK_INTERVAL_US      (12LL * 60 * 60 * 1000 * 1000)
// manifest + signed JWS comfortably fit; oversized responses are truncated
// and fail parsing (treated as a check error, retried on schedule).
#define RESPONSE_BUFFER_SIZE   4096
#define OTA_TASK_STACK_BYTES   8192
#define OTA_TASK_PRIORITY      4
#define MAX_BOOT_CHECK_RETRIES 3
// Transient transport failures mid-download are retried in place before
// falling back to the (12 h) periodic schedule.
#define OTA_DOWNLOAD_ATTEMPTS  3
#define OTA_DOWNLOAD_RETRY_MS  15000
// The boot check is armed by cloudlink's session-ready event (the check
// needs the device JWT that session carries). A short settle lets the
// post-connect burst (twin reports, app handshake) clear before another TLS
// handshake competes for internal RAM; a failed attempt is retried on a
// timer rather than waiting for the next network event.
#define BOOT_CHECK_DELAY_US    (10LL * 1000 * 1000)
#define BOOT_CHECK_RETRY_US    (60LL * 1000 * 1000)

#define URL_BUFFER_SIZE     256
#define UPDATE_ID_SIZE      64
#define VERSION_SIZE        64

static struct {
    bool initialized;
    koios_ota_config_t cfg;
    kp_timer_t periodic_timer;
    kp_timer_t boot_timer;  // one-shot: initial delay and retries of the boot check

    // Guarded by check_mutex: at most one check task at a time.
    kp_mutex_t check_mutex;
    bool check_in_progress;

    volatile bool boot_check_completed;
    volatile bool boot_check_pending;
    int boot_check_retries;

    // Reboot-into-update confirmation still owed to the server.
    bool boot_report_pending;
} s = {
    .boot_check_pending = true,
    .boot_report_pending = true,
};

typedef enum {
    CHECK_RESULT_SUCCESS,
    CHECK_RESULT_UPDATE_STARTED,   // download/flash path ran (device restarts on success)
    CHECK_RESULT_NO_TOKEN,
    CHECK_RESULT_NETWORK_ERROR,
    CHECK_RESULT_PARSE_ERROR,
} check_result_t;

//------------------------------------------------------------------------------
// Status reporting (best-effort; failures never block the update itself)
//------------------------------------------------------------------------------

static bool report_status(const char* token, const char* update_id,
    const char* status, const char* error_code) {
    char url[URL_BUFFER_SIZE];
    snprintf(url, sizeof(url), "%s/v1/ota/updates/%s/status",
        s.cfg.endpoint_url, update_id);

    char body[160];
    if (error_code) {
        snprintf(body, sizeof(body), "{\"status\":\"%s\",\"error_code\":\"%s\"}",
            status, error_code);
    }
    else {
        snprintf(body, sizeof(body), "{\"status\":\"%s\"}", status);
    }

    char* auth = kp_malloc(strlen(token) + 8);
    if (!auth) return false;
    sprintf(auth, "Bearer %s", token);
    kp_http_header_t headers[1] = { { "Authorization", auth } };

    char response[128];
    int http_status = 0;
    int err = kp_http_post_json(url, headers, 1, body,
        response, sizeof(response), &http_status);
    kp_free(auth);

    if (err != 0 || http_status < 200 || http_status >= 300) {
        KP_LOGW(TAG, "Status report '%s' failed (err %d, http %d)",
            status, err, http_status);
        return false;
    }
    return true;
}

// After a reboot into a fresh image, close the loop with the server:
// running the expected version -> confirmed, anything else -> rolled_back.
// Keeps the pending record until a report actually lands.
static void report_boot_outcome(const char* token) {
    if (!s.boot_report_pending) return;

    char update_id[UPDATE_ID_SIZE];
    char expected[VERSION_SIZE];
    if (kp_ota_pending_load(update_id, sizeof(update_id),
        expected, sizeof(expected)) != 0) {
        s.boot_report_pending = false;  // nothing pending
        return;
    }

    char project[VERSION_SIZE], running[VERSION_SIZE];
    kp_ota_get_app_desc(project, sizeof(project), running, sizeof(running));

    bool ok;
    if (strcmp(running, expected) == 0) {
        KP_LOGI(TAG, "Booted update %s (v%s), confirming", update_id, running);
        ok = report_status(token, update_id, "confirmed", NULL);
    }
    else {
        KP_LOGW(TAG, "Expected v%s after update %s but running v%s",
            expected, update_id, running);
        ok = report_status(token, update_id, "rolled_back", "boot_version_mismatch");
    }

    if (ok) {
        kp_ota_pending_clear();
        s.boot_report_pending = false;
    }
}

//------------------------------------------------------------------------------
// Check + apply
//------------------------------------------------------------------------------

typedef struct {
    char update_id[UPDATE_ID_SIZE];
    char version[VERSION_SIZE];
    char* url;         // kp_malloc'd
    char* sha256;      // kp_malloc'd
    size_t size;
} ota_offer_t;

static char* dup_string(const char* str) {
    if (!str) return NULL;
    char* copy = kp_malloc(strlen(str) + 1);
    if (copy) strcpy(copy, str);
    return copy;
}

// GET /v1/ota/check. 204 -> SUCCESS (up to date); 200 -> offer filled in.
// TODO: verify the `signed` JWS against the service JWKS (needs an ES256
// verify port); TLS server authentication is the trust anchor until then.
static check_result_t fetch_offer(const char* token, ota_offer_t* offer) {
    char url[URL_BUFFER_SIZE];
    snprintf(url, sizeof(url), "%s/v1/ota/check", s.cfg.endpoint_url);

    char* auth = kp_malloc(strlen(token) + 8);
    if (!auth) return CHECK_RESULT_NETWORK_ERROR;
    sprintf(auth, "Bearer %s", token);
    kp_http_header_t headers[1] = { { "Authorization", auth } };

    char* response = kp_malloc(RESPONSE_BUFFER_SIZE);
    if (!response) {
        kp_free(auth);
        return CHECK_RESULT_NETWORK_ERROR;
    }

    int status = 0;
    int err = kp_http_get(url, headers, 1, response, RESPONSE_BUFFER_SIZE, &status);
    kp_free(auth);

    check_result_t result;
    if (err != 0) {
        KP_LOGD(TAG, "Check request failed (transport)");
        result = CHECK_RESULT_NETWORK_ERROR;
    }
    else if (status == 204) {
        result = CHECK_RESULT_SUCCESS;
    }
    else if (status == 401 || status == 403) {
        KP_LOGW(TAG, "Check rejected (%d), requesting token refresh", status);
        koios_cloudlink_request_token_refresh();
        result = CHECK_RESULT_NO_TOKEN;
    }
    else if (status != 200) {
        KP_LOGD(TAG, "Check failed (http %d)", status);
        result = CHECK_RESULT_NETWORK_ERROR;
    }
    else {
        result = CHECK_RESULT_PARSE_ERROR;  // until proven otherwise
        cJSON* root = cJSON_Parse(response);
        if (root) {
            cJSON* data = cJSON_GetObjectItem(root, "data");
            cJSON* manifest = cJSON_GetObjectItem(data, "manifest");
            cJSON* artifact = cJSON_GetObjectItem(manifest, "artifact");
            const char* update_id =
                cJSON_GetStringValue(cJSON_GetObjectItem(manifest, "update_id"));
            const char* version =
                cJSON_GetStringValue(cJSON_GetObjectItem(manifest, "version"));
            const char* art_url =
                cJSON_GetStringValue(cJSON_GetObjectItem(artifact, "url"));
            const char* sha256 =
                cJSON_GetStringValue(cJSON_GetObjectItem(artifact, "sha256"));
            cJSON* size = cJSON_GetObjectItem(artifact, "size");

            if (update_id && version && art_url && sha256) {
                strlcpy(offer->update_id, update_id, sizeof(offer->update_id));
                strlcpy(offer->version, version, sizeof(offer->version));
                offer->url = dup_string(art_url);
                offer->sha256 = dup_string(sha256);
                offer->size = cJSON_IsNumber(size)
                    ? (size_t)cJSON_GetNumberValue(size) : 0;
                if (offer->url && offer->sha256) {
                    result = CHECK_RESULT_UPDATE_STARTED;
                }
            }
            cJSON_Delete(root);
        }
        if (result == CHECK_RESULT_PARSE_ERROR) {
            KP_LOGW(TAG, "Unparseable check response");
        }
    }

    kp_free(response);
    return result;
}

// Runs the offer end to end. Restarts the device on success.
static void apply_offer(const char* token, ota_offer_t* offer) {
    char project[VERSION_SIZE], running[VERSION_SIZE];
    kp_ota_get_app_desc(project, sizeof(project), running, sizeof(running));

    // Offer for the version we already run (e.g. re-deploy of the current
    // release): nothing to flash, just close out the update.
    if (strcmp(running, offer->version) == 0) {
        KP_LOGI(TAG, "Offered v%s already running, confirming", offer->version);
        report_status(token, offer->update_id, "confirmed", NULL);
        return;
    }

    KP_LOGI(TAG, "Updating v%s -> v%s (update %s)", running, offer->version,
        offer->update_id);
    report_status(token, offer->update_id, "downloading", NULL);

    char* auth = kp_malloc(strlen(token) + 8);
    if (auth) sprintf(auth, "Bearer %s", token);

    kp_ota_image_t image = {
        .url = offer->url,
        .bearer = auth,
        .sha256_hex = offer->sha256,
        .size = offer->size,
    };

    // The transfer can drop mid-stream (transient TLS/transport errors, a CDN
    // closing the connection). Retry a few times before giving up so a brief
    // glitch doesn't push the whole update back to the 12 h schedule. Only
    // transport failures are retried — a hash/size/flash failure is
    // deterministic (wrong artifact or bad partition), so re-downloading just
    // burns a flash cycle. esp_https_ota_begin re-erases app1 each attempt, so
    // a retry restarts from a clean slate.
    int err = KP_OTA_ERR_DOWNLOAD;
    for (int attempt = 1; attempt <= OTA_DOWNLOAD_ATTEMPTS; attempt++) {
        err = kp_ota_download_and_apply(&image);
        if (err == KP_OTA_OK || err != KP_OTA_ERR_DOWNLOAD) break;
        if (attempt < OTA_DOWNLOAD_ATTEMPTS) {
            KP_LOGW(TAG, "Download attempt %d/%d failed, retrying in %d ms",
                attempt, OTA_DOWNLOAD_ATTEMPTS, OTA_DOWNLOAD_RETRY_MS);
            kp_delay_ms(OTA_DOWNLOAD_RETRY_MS);
        }
    }
    kp_free(auth);

    if (err != KP_OTA_OK) {
        const char* code = (err == KP_OTA_ERR_HASH) ? "failed_hash"
            : (err == KP_OTA_ERR_FLASH) ? "failed_flash"
            : "failed_download";
        KP_LOGE(TAG, "Update failed (%s)", code);
        // Tell the server so the rollout dashboard sees the failure instead
        // of a device stuck in "downloading".
        report_status(token, offer->update_id, "failed", code);
        return;
    }

    // Only now is the new image committed as the next boot partition. Persist
    // the expected version *after* the flash so a crash mid-download can't
    // leave a stale marker that masquerades as a rollback on the next boot.
    kp_ota_pending_save(offer->update_id, offer->version);

    report_status(token, offer->update_id, "rebooting", NULL);
    KP_LOGI(TAG, "Update applied, restarting...");
    kp_ota_restart();
}

static bool perform_update_check(void) {
    // Checks are authenticated with the cloudlink device JWT; without a
    // session yet there is nothing to do (retried on the boot schedule).
    char* token = koios_cloudlink_get_token_copy();
    if (!token) {
        KP_LOGD(TAG, "No device token yet, skipping check");
        return false;
    }

    report_boot_outcome(token);

    ota_offer_t offer = { 0 };
    check_result_t result = fetch_offer(token, &offer);

    bool success = false;
    switch (result) {
    case CHECK_RESULT_SUCCESS:
        KP_LOGI(TAG, "Up to date");
        success = true;
        break;

    case CHECK_RESULT_UPDATE_STARTED:
        // Does not return when the flash succeeds (device restarts).
        apply_offer(token, &offer);
        success = true;
        break;

    case CHECK_RESULT_NO_TOKEN:
    case CHECK_RESULT_NETWORK_ERROR:
    case CHECK_RESULT_PARSE_ERROR:
        break;
    }

    kp_free(offer.url);
    kp_free(offer.sha256);
    kp_free(token);
    return success;
}

//------------------------------------------------------------------------------
// Scheduling: boot check armed by session-ready (+ timed retries), then 12 h
//------------------------------------------------------------------------------

static void start_periodic_timer(void) {
    if (s.periodic_timer) {
        kp_timer_start_periodic(s.periodic_timer, CHECK_INTERVAL_US);
        KP_LOGI(TAG, "Started periodic update timer (12h)");
    }
}

static void ota_check_task(void* arg) {
    bool is_boot_check = arg != NULL;

    bool success = perform_update_check();

    if (is_boot_check) {
        if (success) {
            s.boot_check_completed = true;
            s.boot_check_pending = false;
            start_periodic_timer();
        }
        else {
            s.boot_check_retries++;
            if (s.boot_check_retries >= MAX_BOOT_CHECK_RETRIES) {
                KP_LOGW(TAG, "Boot check failed after %d retries, giving up",
                    s.boot_check_retries);
                s.boot_check_completed = true;
                s.boot_check_pending = false;
                start_periodic_timer();
            }
            else {
                KP_LOGW(TAG, "Boot check failed (attempt %d/%d), retrying in %llds",
                    s.boot_check_retries, MAX_BOOT_CHECK_RETRIES,
                    (long long)(BOOT_CHECK_RETRY_US / 1000000));
                if (s.boot_timer) {
                    kp_timer_stop(s.boot_timer);
                    kp_timer_start_once(s.boot_timer, BOOT_CHECK_RETRY_US);
                }
            }
        }
    }

    if (kp_mutex_take(s.check_mutex, KP_WAIT_FOREVER)) {
        s.check_in_progress = false;
        kp_mutex_give(s.check_mutex);
    }
}

static void spawn_check_task(bool is_boot_check) {
    if (!s.check_mutex || !kp_mutex_take(s.check_mutex, 100)) return;
    bool claimed = false;
    if (!s.check_in_progress) {
        s.check_in_progress = true;
        claimed = true;
    }
    kp_mutex_give(s.check_mutex);
    if (!claimed) return;

    if (!kp_task_spawn("ota_check", ota_check_task,
        is_boot_check ? (void*)1 : NULL, OTA_TASK_STACK_BYTES, OTA_TASK_PRIORITY)) {
        KP_LOGE(TAG, "Failed to create OTA check task");
        if (kp_mutex_take(s.check_mutex, KP_WAIT_FOREVER)) {
            s.check_in_progress = false;
            kp_mutex_give(s.check_mutex);
        }
    }
}

static void periodic_timer_cb(void* arg) {
    (void)arg;
    if (kp_net_is_connected()) {
        spawn_check_task(false);
    }
}

static void boot_timer_cb(void* arg) {
    (void)arg;
    if (!s.boot_check_pending) return;
    if (!kp_net_is_connected()) {
        // Network went away again; session-ready re-arms us when it is back.
        KP_LOGD(TAG, "Boot check deferred: offline");
        return;
    }
    spawn_check_task(true);
}

static void arm_boot_check(int64_t delay_us) {
    if (!s.boot_timer || !s.boot_check_pending) return;
    kp_timer_stop(s.boot_timer);
    kp_timer_start_once(s.boot_timer, delay_us);
}

void koios_ota_init(const koios_ota_config_t* config) {
    if (s.initialized) return;
    if (config) s.cfg = *config;
    if (!s.cfg.endpoint_url) s.cfg.endpoint_url = DEFAULT_ENDPOINT_URL;

    s.check_mutex = kp_mutex_create();
    s.periodic_timer = kp_timer_create("ota_periodic", periodic_timer_cb, NULL);
    s.boot_timer = kp_timer_create("ota_boot", boot_timer_cb, NULL);
    if (!s.check_mutex || !s.periodic_timer || !s.boot_timer) {
        KP_LOGE(TAG, "Failed to allocate primitives");
        if (s.periodic_timer) { kp_timer_delete(s.periodic_timer); s.periodic_timer = NULL; }
        if (s.boot_timer) { kp_timer_delete(s.boot_timer); s.boot_timer = NULL; }
        if (s.check_mutex) { kp_mutex_delete(s.check_mutex); s.check_mutex = NULL; }
        return;
    }
    s.initialized = true;

    // The session may already be up (init after connect) — cloudlink fires no
    // synthetic session-ready, so arm the boot check ourselves.
    if (koios_cloudlink_is_ready()) {
        KP_LOGI(TAG, "Cloud session already ready, arming boot check");
        arm_boot_check(BOOT_CHECK_DELAY_US);
    }

    KP_LOGI(TAG, "Initialized (endpoint: %s)", s.cfg.endpoint_url);
}

void koios_ota_on_session_ready(void) {
    if (!s.initialized || !s.boot_check_pending) return;
    KP_LOGI(TAG, "Cloud session ready, boot check in %llds",
        (long long)(BOOT_CHECK_DELAY_US / 1000000));
    arm_boot_check(BOOT_CHECK_DELAY_US);
}

bool koios_ota_boot_check_completed(void) {
    return s.boot_check_completed;
}

void koios_ota_check_now(void) {
    if (!s.initialized) return;
    if (kp_net_is_connected()) {
        spawn_check_task(false);
    }
}
