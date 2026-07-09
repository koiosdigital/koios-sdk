#pragma once

// Device identity port for mTLS. The private key never crosses this
// interface: the key context is an opaque handle the core passes straight
// through to kp_websocket (on ESP32 it is an esp_ds_data_ctx_t* driving the
// DS peripheral). Ports without hardware identity return not-ready and the
// app uses API-key auth instead.

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// True once a client certificate is provisioned and the key is usable.
bool kp_identity_ready(void);

// PEM client certificate. On success *pem is a kp_malloc'd, NUL-terminated
// buffer the caller frees with kp_free; *len is strlen(*pem). Nonzero on error.
int kp_identity_get_client_cert(char** pem, size_t* len);

// Opaque TLS client-key context for kp_websocket. NULL on error. Release
// with kp_identity_release_key_ctx when no longer needed.
void* kp_identity_get_key_ctx(void);
void  kp_identity_release_key_ctx(void* ctx);

#ifdef __cplusplus
}
#endif
