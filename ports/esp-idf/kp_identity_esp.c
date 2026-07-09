// Device identity over kd_common's crypto module (device cert in NVS,
// private key in the DS peripheral — it never leaves hardware; the "key
// context" handed out here is the DS parameter block esp-tls consumes).

#include "koios/port/kp_identity.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"

#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include <kd_common.h>
#include <stdlib.h>

static const char* TAG = "kp_identity";

bool kp_identity_ready(void) {
    return kd_common_crypto_get_state() == CRYPTO_STATE_VALID_CERT;
}

int kp_identity_get_client_cert(char** pem, size_t* len) {
    *pem = NULL;
    *len = 0;

    size_t cert_len = 0;
    esp_err_t ret = kd_common_get_device_cert(NULL, &cert_len);
    if (ret != ESP_OK || cert_len == 0) {
        KP_LOGE(TAG, "Failed to get device certificate length: %d", ret);
        return -1;
    }

    char* buf = kp_calloc(cert_len + 1, 1);
    if (!buf) return -1;

    ret = kd_common_get_device_cert(buf, &cert_len);
    if (ret != ESP_OK) {
        KP_LOGE(TAG, "Failed to get device certificate: %d", ret);
        kp_free(buf);
        return -1;
    }

    *pem = buf;
    *len = cert_len;
    return 0;
}

void* kp_identity_get_key_ctx(void) {
    return kd_common_crypto_get_ctx();
}

void kp_identity_release_key_ctx(void* ctx) {
    if (!ctx) return;
    esp_ds_data_ctx_t* ds = (esp_ds_data_ctx_t*)ctx;
    free(ds->esp_ds_data);
    free(ds);
}

#else  // !CONFIG_KD_COMMON_CRYPTO_ENABLE

bool kp_identity_ready(void) { return false; }
int kp_identity_get_client_cert(char** pem, size_t* len) { (void)pem; (void)len; return -1; }
void* kp_identity_get_key_ctx(void) { return (void*)0; }
void kp_identity_release_key_ctx(void* ctx) { (void)ctx; }

#endif
