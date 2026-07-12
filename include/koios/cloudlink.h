#pragma once

// Cloudlink: the persistent device <-> Koios cloud WebSocket session.
//
// Owns the connection lifecycle end to end: waits for network (and identity,
// for mTLS), connects, expects a `welcome` control frame, manages the device
// JWT it carries, reconnects with jittered exponential backoff, and escalates
// persistent failures (socket -> network reset -> device restart).
//
// Two auth modes, matching the vn worker:
//   KOIOS_CLOUD_AUTH_MTLS    wss://vn-sec.koios.sh — client cert via
//                            kp_identity; waits until the identity is ready.
//   KOIOS_CLOUD_AUTH_API_KEY wss://vn.koios.sh — Authorization: Bearer <key>
//                            on the handshake. A provisioning key may cause
//                            the server to mint a device key, delivered once
//                            in the welcome frame (on_api_key_issued).
//
// Text frames are the control channel (welcome/token/twin.*), handled here.
// Binary frames are the app's protocol; they arrive via on_message and are
// sent with koios_cloudlink_send().

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KOIOS_CLOUD_AUTH_MTLS,
    KOIOS_CLOUD_AUTH_API_KEY,
} koios_cloud_auth_mode_t;

typedef enum {
    KOIOS_CLOUD_STATE_WAITING,     // no network / identity not ready
    KOIOS_CLOUD_STATE_CONNECTING,  // between attempts or awaiting welcome
    KOIOS_CLOUD_STATE_READY,       // session established (welcome received)
} koios_cloud_state_t;

typedef struct {
    const char* url;
    koios_cloud_auth_mode_t auth_mode;

    // API-key mode only: the credential sent on the handshake. Cloudlink
    // copies it; the app may free its own buffer after init.
    const char* api_key;

    // Build variant, reported to the cloud as twin reported state `fw.variant`
    // on session ready — it becomes a device label the platform can target OTA
    // deployments on, e.g. "v9_64x32" (typically FIRMWARE_VARIANT). Reported
    // alongside `fw.class` (the silicon target, sourced by the SDK from
    // CONFIG_IDF_TARGET), `fw.project` (the IDF project name) and `fw.version`.
    // Optional; not copied — pass a string with static lifetime.
    const char* variant;

    size_t max_msg_size;  // 0 -> 16 KiB. Inbound messages above this are dropped.
    size_t queue_depth;   // 0 -> 8. Outbox capacity in messages.

    // Coarse connection state for UI. Optional.
    void (*on_state_change)(koios_cloud_state_t state);

    // Session established / lost. on_disconnect fires only if the session
    // had been ready. Optional.
    void (*on_session_ready)(void);
    void (*on_disconnect)(void);

    // Complete inbound binary message. Runs in cloudlink's context; the
    // buffer is freed after return. Required.
    void (*on_message)(const uint8_t* data, size_t len);

    // Unhandled text control frame (anything beyond welcome/token/twin.*),
    // for app-level extensions. Optional.
    void (*on_control)(const char* json, size_t len);

    // API-key mode: server minted a device key for this device (sent once,
    // in the welcome frame). Persist it and use it for future connects.
    // Cloudlink switches to it in-memory for the current session. Optional.
    void (*on_api_key_issued)(const char* api_key);

    // Timezone hint from the welcome frame. Optional.
    void (*on_timezone)(const char* tz);

    // Extra readiness gate polled before connecting (1 Hz). Optional; mTLS
    // mode already gates on kp_identity_ready().
    bool (*ready_gate)(void);
} koios_cloudlink_config_t;

void koios_cloudlink_init(const koios_cloudlink_config_t* config);
void koios_cloudlink_deinit(void);

// True while the socket is up (welcome may still be pending).
bool koios_cloudlink_is_connected(void);

// True once the session is established (welcome received, not yet dropped).
bool koios_cloudlink_is_ready(void);

// Queue one binary message. The data is copied. False if the outbox is full
// or cloudlink is not initialized; queued messages survive a reconnect.
bool koios_cloudlink_send(const void* data, size_t len);

// Send a text control frame immediately (no queueing). False if offline.
bool koios_cloudlink_send_text(const char* text);

// Copy of the current device JWT, kp_malloc'd (free with kp_free), or NULL
// if none has been issued yet.
char* koios_cloudlink_get_token_copy(void);

// Copy the device UUID (assigned by the platform, delivered in the welcome
// frame) into `out`. False if no session has been established yet. `out` is
// always NUL-terminated; 48 bytes is enough for any UUID.
bool koios_cloudlink_get_device_id(char* out, size_t out_size);

// Ask the server for a fresh device JWT (rate-limited to one request per
// 30 s). Call after a 401/403 on an HTTP API that consumes the token.
void koios_cloudlink_request_token_refresh(void);

#ifdef __cplusplus
}
#endif
