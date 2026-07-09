#include "koios/port/kp_ota.h"
#include "koios/port/kp_log.h"

#include <esp_https_ota.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <esp_app_desc.h>
#include <esp_system.h>

#include <kd_http.h>

#include <string.h>

static const char* TAG = "kp_ota";

#define OTA_BUFFER_SIZE 4096

int kp_ota_download_and_apply(const char* url) {
    // esp_https_ota owns its client internally; hold the app-wide HTTP lock
    // so the download's TLS session doesn't overlap other fetches.
    if (!kd_http_lock(60000)) {
        KP_LOGW(TAG, "HTTP client busy, deferring update");
        return -1;
    }

    esp_http_client_config_t http_config = {
        .url = url,
        .buffer_size = OTA_BUFFER_SIZE,
        .buffer_size_tx = OTA_BUFFER_SIZE,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    esp_err_t err = esp_https_ota(&ota_config);
    kd_http_unlock();
    if (err != ESP_OK) {
        KP_LOGE(TAG, "Update failed: %s", esp_err_to_name(err));
        return -1;
    }

    KP_LOGI(TAG, "Update complete, restarting...");
    esp_restart();
    return 0;  // Never reached
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
