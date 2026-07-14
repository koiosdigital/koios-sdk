#include "koios/port/kp_ota.h"
#include "koios/port/kp_log.h"

#include <esp_https_ota.h>
#include <esp_ota_ops.h>
#include <esp_http_client.h>
#include <spi_flash_mmap.h>
#include <esp_crt_bundle.h>
#include <esp_app_desc.h>
#include <esp_system.h>
#include <psa/crypto.h>
#include <nvs.h>

#include <kd_http.h>

#include <string.h>
#include <stdio.h>

static const char* TAG = "kp_ota";

#define OTA_BUFFER_SIZE 6 * 1024

#define NVS_NAMESPACE   "koios_ota"
#define NVS_KEY_UPDATE  "pend_update"
#define NVS_KEY_VERSION "pend_version"

//------------------------------------------------------------------------------
// Download + flash
//------------------------------------------------------------------------------

// The image sha256 is computed over the response body as esp_https_ota
// streams it (HTTP_EVENT_ON_DATA fires before the OTA layer consumes each
// chunk) and compared against the manifest BEFORE esp_https_ota_finish()
// commits the new boot partition.
typedef struct {
    psa_hash_operation_t sha;
    size_t received;
} download_ctx_t;

static download_ctx_t s_dl;
static const char* s_bearer;  // valid for the duration of one download

static esp_err_t ota_http_event_handler(esp_http_client_event_t* evt) {
    if (evt && evt->event_id == HTTP_EVENT_ON_DATA && evt->data && evt->data_len > 0) {
        psa_hash_update(&s_dl.sha, evt->data, evt->data_len);
        s_dl.received += evt->data_len;
    }
    return ESP_OK;
}

static esp_err_t ota_http_client_init_cb(esp_http_client_handle_t client) {
    if (s_bearer) {
        return esp_http_client_set_header(client, "Authorization", s_bearer);
    }
    return ESP_OK;
}

static bool sha256_matches(const char* expected_hex) {
    uint8_t digest[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t digest_len = 0;
    psa_status_t status = psa_hash_finish(&s_dl.sha, digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS || digest_len != sizeof(digest)) {
        KP_LOGE(TAG, "psa_hash_finish failed: %d", (int)status);
        return false;
    }

    char actual_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&actual_hex[i * 2], "%02x", digest[i]);
    }
    if (strcasecmp(actual_hex, expected_hex) != 0) {
        KP_LOGE(TAG, "Image sha256 mismatch: got %s, expected %s",
            actual_hex, expected_hex);
        return false;
    }
    return true;
}

int kp_ota_download_and_apply(const kp_ota_image_t* image) {
    if (!image || !image->url) return KP_OTA_ERR_DOWNLOAD;

    // esp_https_ota owns its client internally; hold the app-wide HTTP lock
    // so the download's TLS session doesn't overlap other fetches.
    if (!kd_http_lock(60000)) {
        KP_LOGW(TAG, "HTTP client busy, deferring update");
        return KP_OTA_ERR_DOWNLOAD;
    }

    psa_status_t psa_status = psa_crypto_init();
    if (psa_status == PSA_SUCCESS) {
        s_dl.sha = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
        psa_status = psa_hash_setup(&s_dl.sha, PSA_ALG_SHA_256);
    }
    if (psa_status != PSA_SUCCESS) {
        KP_LOGE(TAG, "PSA hash setup failed: %d", (int)psa_status);
        kd_http_unlock();
        return KP_OTA_ERR_DOWNLOAD;
    }
    s_dl.received = 0;
    s_bearer = image->bearer;

    esp_http_client_config_t http_config = {
        .url = image->url,
        .buffer_size = OTA_BUFFER_SIZE,
        .buffer_size_tx = OTA_BUFFER_SIZE,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .event_handler = ota_http_event_handler,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
        .http_client_init_cb = ota_http_client_init_cb,
    };

    int result = KP_OTA_ERR_DOWNLOAD;
    esp_https_ota_handle_t handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &handle);
    if (err != ESP_OK) {
        KP_LOGE(TAG, "OTA begin failed: %s", esp_err_to_name(err));
        goto out;
    }

    while ((err = esp_https_ota_perform(handle)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
    }

    if (err != ESP_OK || !esp_https_ota_is_complete_data_received(handle)) {
        KP_LOGE(TAG, "OTA download failed: %s", esp_err_to_name(err));
        esp_https_ota_abort(handle);
        result = (err == ESP_ERR_OTA_VALIDATE_FAILED || err == ESP_ERR_INVALID_VERSION
            || err == ESP_ERR_FLASH_OP_FAIL || err == ESP_ERR_OTA_BASE)
            ? KP_OTA_ERR_FLASH : KP_OTA_ERR_DOWNLOAD;
        goto out;
    }

    if (image->size && s_dl.received != image->size) {
        KP_LOGE(TAG, "Image size mismatch: got %u, expected %u",
            (unsigned)s_dl.received, (unsigned)image->size);
        esp_https_ota_abort(handle);
        result = KP_OTA_ERR_HASH;
        goto out;
    }
    if (image->sha256_hex && !sha256_matches(image->sha256_hex)) {
        esp_https_ota_abort(handle);
        result = KP_OTA_ERR_HASH;
        goto out;
    }

    // Validates the image and commits it as the next boot partition.
    err = esp_https_ota_finish(handle);
    if (err != ESP_OK) {
        KP_LOGE(TAG, "OTA finish failed: %s", esp_err_to_name(err));
        result = KP_OTA_ERR_FLASH;
        goto out;
    }

    KP_LOGI(TAG, "Update flashed and staged for next boot");
    result = KP_OTA_OK;

out:
    s_bearer = NULL;
    // No-op if psa_hash_finish already terminated the operation.
    psa_hash_abort(&s_dl.sha);
    kd_http_unlock();
    return result;
}

void kp_ota_restart(void) {
    esp_restart();
}

void kp_ota_get_app_desc(char* project, size_t project_size,
    char* version, size_t version_size) {
    const esp_app_desc_t* desc = esp_app_get_description();
    if (project && project_size) {
        strlcpy(project, desc->project_name, project_size);
    }
    if (version && version_size) {
        strlcpy(version, desc->version, version_size);
    }
}

//------------------------------------------------------------------------------
// Pending-update record (survives the reboot into the new image)
//------------------------------------------------------------------------------

int kp_ota_pending_save(const char* update_id, const char* version) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) return -1;
    esp_err_t err = nvs_set_str(nvs, NVS_KEY_UPDATE, update_id);
    if (err == ESP_OK) err = nvs_set_str(nvs, NVS_KEY_VERSION, version);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return (err == ESP_OK) ? 0 : -1;
}

int kp_ota_pending_load(char* update_id, size_t id_size,
    char* version, size_t version_size) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return -1;
    size_t len = id_size;
    esp_err_t err = nvs_get_str(nvs, NVS_KEY_UPDATE, update_id, &len);
    if (err == ESP_OK) {
        len = version_size;
        err = nvs_get_str(nvs, NVS_KEY_VERSION, version, &len);
    }
    nvs_close(nvs);
    return (err == ESP_OK) ? 0 : -1;
}

void kp_ota_pending_clear(void) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) return;
    nvs_erase_key(nvs, NVS_KEY_UPDATE);
    nvs_erase_key(nvs, NVS_KEY_VERSION);
    nvs_commit(nvs);
    nvs_close(nvs);
}
