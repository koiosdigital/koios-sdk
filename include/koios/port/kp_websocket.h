#pragma once

// WebSocket client port. The port owns transport details — TLS, ping/pong,
// and fragment reassembly — and delivers only complete messages. The core
// owns connection policy: reconnect, backoff, session state.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kp_ws* kp_ws_t;

typedef enum {
    KP_WS_EV_CONNECTED,     // data/len unused
    KP_WS_EV_DISCONNECTED,  // covers close and transport error; data points to
                            // a kp_ws_disconnect_info_t (len == sizeof) or is
                            // NULL when the port cannot classify the failure
    KP_WS_EV_MSG_TEXT,      // complete text message
    KP_WS_EV_MSG_BINARY,    // complete binary message
} kp_ws_event_type_t;

// Why the socket went down. The core escalates (network reset, restart) only
// on KP_WS_FAIL_LINK: nothing answered, so the local link is suspect. A
// server that answered — with an HTTP status on the upgrade, a TLS alert or
// certificate rejection, a close frame, a TCP reset — proves the link works.
typedef enum {
    KP_WS_FAIL_UNKNOWN = 0,  // no diagnostics; the core treats it as a link failure
    KP_WS_FAIL_LINK,         // DNS / TCP connect / socket or pong timeout
    KP_WS_FAIL_SERVER,       // the peer answered (HTTP status, TLS alert, cert rejection, close)
} kp_ws_fail_class_t;

typedef struct {
    kp_ws_fail_class_t fail_class;
    bool was_connected;     // the socket had reached CONNECTED before dropping
    int  handshake_status;  // HTTP status of the upgrade response, 0 if none
    int  tls_err;           // port-specific TLS stack error code, 0 if none
    int  sock_errno;        // socket errno, 0 if none
} kp_ws_disconnect_info_t;

// Fired from the port's transport context. The data pointer is only valid
// for the duration of the callback.
typedef void (*kp_ws_event_fn)(void* arg, kp_ws_event_type_t ev,
                               const uint8_t* data, size_t len);

typedef struct {
    const char* url;  // wss://...

    // mTLS client auth (all three set together, or all zero for none).
    const char* client_cert_pem;
    size_t      client_cert_len;   // bytes including NUL terminator
    void*       client_key_ctx;    // opaque, from kp_identity_get_key_ctx()

    // Bearer credential sent as an Authorization header on the handshake
    // (API-key auth). NULL for none.
    const char* bearer;

    size_t max_rx_size;  // messages larger than this are dropped

    kp_ws_event_fn on_event;
    void*          event_arg;
} kp_ws_config_t;

// Create the client and start connecting asynchronously. Events (including
// the first CONNECTED/DISCONNECTED) arrive via on_event. NULL on setup error.
// The port must NOT auto-reconnect; exactly one DISCONNECTED is delivered per
// attempt and the core decides when to try again.
kp_ws_t kp_ws_open(const kp_ws_config_t* cfg);

bool kp_ws_is_connected(kp_ws_t ws);

// Send one complete message. Blocks up to timeout_ms. False unless every
// byte was written.
bool kp_ws_send(kp_ws_t ws, const void* data, size_t len, bool binary,
                uint32_t timeout_ms);

// Tear down and free. Waits up to timeout_ms for the port's transport task
// to exit (it may be inside the event callback). Returns true when the
// client is fully destroyed. On timeout the port DETACHES the handle — no
// further events are delivered for it and its resources are reclaimed in
// the background once the task exits — and returns false. UINT32_MAX
// (KP_WAIT_FOREVER) waits indefinitely. Safe to call from any task except
// the event callback. No events are delivered once this has been called.
bool kp_ws_close_bounded(kp_ws_t ws, uint32_t timeout_ms);

// kp_ws_close_bounded(ws, KP_WAIT_FOREVER).
void kp_ws_close(kp_ws_t ws);

#ifdef __cplusplus
}
#endif
