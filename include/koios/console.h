#pragma once

// Console sessions: an operator reaches the device through the Koios gateway
// while the device stays behind its outbound link.
//
// The gateway asks over cloudlink:
//
//   {"type":"console.open","session":"<uuid>","target":"ssh"}
//
// The device decides. It takes the session only if console is enabled here
// and `target` is a name in its own configuration; the cloud names a target,
// it never names an address. The device then opens a second WebSocket, for
// this session only, to the gateway it is already connected to
// (<cloud url>/v1/console/sessions/<uuid>/device, with its device JWT and, on
// an mTLS gateway, its certificate) and joins it to the target once the
// operator is there. Otherwise it answers
//
//   {"type":"console.status","session":"<uuid>","state":"refused","reason":"..."}
//
// On Linux a target is a local TCP address, a Unix socket or a program started
// for the session. The target named `shell` is a login shell on a terminal
// (koios-shell), which the Koios console's terminal opens in the browser; any
// other is a plain byte stream to a service on the device (docs/linux.md).
// What a session is joined to is the port's business (port/kp_console.h).
//
// Off unless the build defines CONFIG_KOIOS_SDK_CONSOLE_ENABLE and the
// application calls koios_console_init(). A device without it refuses every
// session, so the operator is told at once instead of waiting.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* name;     // what the cloud may ask for: [a-z0-9_-], e.g. "ssh"
    const char* address;  // what it means here; on Linux host:port, unix:/path or exec:/path
} koios_console_target_t;

typedef struct {
    // The cloud URL cloudlink connects to (wss://vn-sec.koios.sh). Session
    // sockets go to the same origin and nowhere else.
    const char* url;
    // Present the device identity on the session socket too (an mTLS gateway
    // demands it at its edge).
    bool mtls;
    // The targets a session may be joined to. Copied.
    const koios_console_target_t* targets;
    size_t target_count;
    // Sessions at a time. 0 -> 4.
    uint8_t max_sessions;
} koios_console_config_t;

// Allow console sessions to the configured targets. Call after
// koios_cloudlink_init().
void koios_console_init(const koios_console_config_t* config);

// Called by cloudlink with a `console.open` frame. Never blocks: the session
// runs on its own task.
struct cJSON;
void koios_console_on_open(const struct cJSON* frame);

#ifdef __cplusplus
}
#endif
