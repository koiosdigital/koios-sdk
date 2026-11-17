// Console sessions on Linux: the session's WebSocket joined to a local TCP
// address (console_stream.c does the work).

#include "koios/port/kp_console.h"
#include "koios/port/kp_log.h"
#include "console_stream.h"

static const char* TAG = "kp_console";

int kp_console_run(const kp_console_session_t* session) {
    const ks_config_t cfg = {
        .role = KS_ROLE_DEVICE,
        .url = session->url,
        .bearer = session->bearer,
        .present_identity = session->mtls,
        .target_address = session->target_address,
        .in_fd = -1,
        .out_fd = -1,
    };
    char reason[200] = "";
    const int rc = ks_run(&cfg, reason, sizeof(reason));
    if (rc != KS_OK) KP_LOGW(TAG, "session %s: %s", session->session_id, reason[0] ? reason : "did not start");
    return rc == KS_OK ? 0 : -1;
}
