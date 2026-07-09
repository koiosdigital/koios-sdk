#include "koios/ota.h"

#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_net.h"
#include "koios/port/kp_http.h"
#include "koios/port/kp_ota.h"

#include <cJSON.h>
#include <string.h>
#include <stdlib.h>

static const char* TAG = "koios_ota";

#define DEFAULT_ENDPOINT_URL "https://firmware.api.koiosdigital.net"

#define CHECK_INTERVAL_US      (12LL * 60 * 60 * 1000 * 1000)
#define RESPONSE_BUFFER_SIZE   512
#define OTA_TASK_STACK_BYTES   12288
#define OTA_TASK_PRIORITY      10
#define MAX_BOOT_CHECK_RETRIES 3
// Boot check waits out the post-IP rush (SNTP, TZ fetch, mDNS, WS mTLS
// handshake) so its TLS handshake doesn't compete for internal RAM.
#define BOOT_CHECK_DELAY_MS    30000

static struct {
    koios_ota_config_t cfg;
    kp_timer_t periodic_timer;

    // Guarded by check_mutex: at most one check task at a time.
    kp_mutex_t check_mutex;
    bool check_in_progress;

    volatile bool boot_check_completed;
    volatile bool boot_check_pending;
    int boot_check_retries;
} s = {
    .boot_check_pending = true,
};

typedef enum {
    CHECK_RESULT_SUCCESS,
    CHECK_RESULT_UPDATE_AVAILABLE,
    CHECK_RESULT_NETWORK_ERROR,
    CHECK_RESULT_PARSE_ERROR,
} check_result_t;

static check_result_t check_for_update(char** out_url) {
    *out_url = NULL;

    char project[64] = { 0 };
    char version[64] = { 0 };
    kp_ota_get_app_desc(project, sizeof(project), version, sizeof(version));

    kp_http_header_t headers[3] = {
        { "x-firmware-project", project },
        { "x-firmware-version", version },
        { "x-firmware-variant", s.cfg.variant },  // dropped below if unset
    };
    size_t header_count = s.cfg.variant ? 3 : 2;

    char response[RESPONSE_BUFFER_SIZE] = { 0 };
    int status = 0;
    int err = kp_http_get(s.cfg.endpoint_url, headers, header_count,
        response, sizeof(response), &status);

    if (err != 0 || status != 200) {
        KP_LOGD(TAG, "HTTP request failed (err: %d, status: %d)", err, status);
        return CHECK_RESULT_NETWORK_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    if (!root) {
        KP_LOGD(TAG, "Failed to parse response");
        return CHECK_RESULT_PARSE_ERROR;
    }

    cJSON* update_item = cJSON_GetObjectItem(root, "update_available");
    if (!update_item) {
        KP_LOGD(TAG, "Missing update_available field");
        cJSON_Delete(root);
        return CHECK_RESULT_PARSE_ERROR;
    }

    if (cJSON_IsFalse(update_item)) {
        cJSON_Delete(root);
        return CHECK_RESULT_SUCCESS;
    }

    cJSON* url_item = cJSON_GetObjectItem(root, "ota_url");
    const char* url = cJSON_GetStringValue(url_item);
    if (!url || !url[0]) {
        KP_LOGW(TAG, "Update available but no valid URL");
        cJSON_Delete(root);
        return CHECK_RESULT_SUCCESS;
    }

    *out_url = kp_malloc(strlen(url) + 1);
    if (*out_url) strcpy(*out_url, url);
    cJSON_Delete(root);
    return *out_url ? CHECK_RESULT_UPDATE_AVAILABLE : CHECK_RESULT_NETWORK_ERROR;
}

static bool perform_update_check(void) {
    char* ota_url = NULL;
    check_result_t result = check_for_update(&ota_url);

    bool success = false;
    switch (result) {
    case CHECK_RESULT_SUCCESS:
        KP_LOGI(TAG, "Up to date");
        success = true;
        break;

    case CHECK_RESULT_UPDATE_AVAILABLE:
        KP_LOGI(TAG, "Update available, downloading...");
        // Does not return on success (device restarts).
        if (kp_ota_download_and_apply(ota_url) != 0) {
            KP_LOGE(TAG, "Update failed");
        }
        success = true;
        break;

    case CHECK_RESULT_NETWORK_ERROR:
    case CHECK_RESULT_PARSE_ERROR:
        break;
    }

    kp_free(ota_url);
    return success;
}

static void start_periodic_timer(void) {
    if (s.periodic_timer) {
        kp_timer_start_periodic(s.periodic_timer, CHECK_INTERVAL_US);
        KP_LOGI(TAG, "Started periodic update timer (12h)");
    }
}

static void ota_check_task(void* arg) {
    bool is_boot_check = arg != NULL;

    if (is_boot_check) {
        kp_delay_ms(BOOT_CHECK_DELAY_MS);
    }

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
                KP_LOGW(TAG, "Boot check failed (attempt %d/%d), will retry",
                    s.boot_check_retries, MAX_BOOT_CHECK_RETRIES);
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

static void ota_on_net_connect(void) {
    if (s.boot_check_pending) {
        KP_LOGI(TAG, "Network up, starting boot check");
        spawn_check_task(true);
    }
}

void koios_ota_init(const koios_ota_config_t* config) {
    if (config) s.cfg = *config;
    if (!s.cfg.endpoint_url) s.cfg.endpoint_url = DEFAULT_ENDPOINT_URL;

    s.check_mutex = kp_mutex_create();
    s.periodic_timer = kp_timer_create("ota_periodic", periodic_timer_cb, NULL);
    if (!s.check_mutex || !s.periodic_timer) {
        KP_LOGE(TAG, "Failed to allocate primitives");
        return;
    }

    kp_net_subscribe(ota_on_net_connect, NULL);

    // Net may already be up (init after connect) — kp_net_subscribe fires no
    // synthetic events, so kick the boot check ourselves.
    if (kp_net_is_connected() && s.boot_check_pending) {
        spawn_check_task(true);
    }

    KP_LOGI(TAG, "Initialized (endpoint: %s)", s.cfg.endpoint_url);
}

bool koios_ota_boot_check_completed(void) {
    return s.boot_check_completed;
}

void koios_ota_check_now(void) {
    if (kp_net_is_connected()) {
        spawn_check_task(false);
    }
}
