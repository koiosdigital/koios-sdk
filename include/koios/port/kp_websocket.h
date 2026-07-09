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
    KP_WS_EV_DISCONNECTED,  // covers close and transport error; data/len unused
    KP_WS_EV_MSG_TEXT,      // complete text message
    KP_WS_EV_MSG_BINARY,    // complete binary message
} kp_ws_event_type_t;

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
// The port must NOT auto-reconnect; one DISCONNECTED is delivered per attempt
// and the core decides when to try again.
kp_ws_t kp_ws_open(const kp_ws_config_t* cfg);

bool kp_ws_is_connected(kp_ws_t ws);

// Send one complete message. Blocks up to timeout_ms. False on failure.
bool kp_ws_send(kp_ws_t ws, const void* data, size_t len, bool binary,
                uint32_t timeout_ms);

// Tear down and free. Safe to call from any task except the event callback.
void kp_ws_close(kp_ws_t ws);

#ifdef __cplusplus
}
#endif
