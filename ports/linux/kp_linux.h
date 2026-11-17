#pragma once

// Internal to the Linux port: the stored configuration and helpers the kp_*
// files share. Not installed.

#include "koios/linux.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The stored copy of koios_linux_config_t (every string owned, never NULL
// where a default exists).
typedef struct {
    char* cert_file;
    char* extra_chain_file;
    char* key;
    char* identity_ready_file;
    char* ca_file;
    char* device_class;
    char* project;
    char* version;
    char* state_dir;
    char* runtime_dir;
    size_t log_ring_bytes;
    int log_level;
    bool capture_own_logs;
    char* storage_path;
    char* net_iface;
    char* ota_staging_dir;
    char* ota_apply_cmd;
    char* ota_restart_cmd;
    void (*restart_handler)(void);
} kp_linux_cfg_t;

const kp_linux_cfg_t* kp_linux_cfg(void);

// What kp_identity_get_key_ctx() hands to kp_websocket: the private key as
// OpenSSL sees it. For a provider key (PKCS#11) the EVP_PKEY is a handle; the
// key material stays with the provider.
typedef struct {
    EVP_PKEY* pkey;
} kp_linux_key_ctx_t;

// Wait on cond (mutex held) for at most timeout_ms on the monotonic clock.
// Returns false on timeout. KP_WAIT_FOREVER waits without limit.
bool kp_linux_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex, uint32_t timeout_ms);
// Initialise a condition variable that kp_linux_cond_wait() can use.
void kp_linux_cond_init(pthread_cond_t* cond);

// mkdir -p. Returns 0 when the directory exists afterwards.
int kp_linux_mkdirs(const char* path, int mode);

// Read a whole file into a malloc'd, NUL-terminated buffer. NULL on error.
char* kp_linux_read_file(const char* path, size_t* len);

// The capture entry of the log store (kp_logstore_linux.c).
void kp_linux_logstore_push(int level, const char* tag, const char* msg, int64_t ts_ms);
