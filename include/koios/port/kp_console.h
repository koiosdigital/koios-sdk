#pragma once

// Console session port. The core decides whether a session is taken
// (core/console.c); the port carries it: it opens the session's WebSocket and
// joins it to the target.

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* session_id;
    const char* url;             // wss://<gateway>/v1/console/sessions/<id>/device
    const char* bearer;          // the device JWT
    bool mtls;                   // also present the device identity (kp_identity)
    const char* target_name;
    const char* target_address;  // from the device's own configuration
} kp_console_session_t;

// Run one session to its end; blocking. Returns 0 when the stream ran, nonzero
// when it never started (the gateway refused the socket, the target could not
// be reached, the operator never came).
int kp_console_run(const kp_console_session_t* session);

#ifdef __cplusplus
}
#endif
