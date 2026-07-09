#pragma once

// Network connectivity port. "Connected" means the interface has an IP and
// outbound traffic is plausible — not that any particular server is reachable.

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*kp_net_event_fn)(void);

bool kp_net_is_connected(void);

// Register connectivity callbacks. Either may be NULL. The port supports at
// least 4 subscribers (cloudlink + OTA + app slack). Callbacks fire from the
// port's event context; treat like an ISR-adjacent context and defer real work.
void kp_net_subscribe(kp_net_event_fn on_connect, kp_net_event_fn on_disconnect);

// Bounce the interface as a recovery measure (e.g. WiFi disconnect and let
// the platform's reconnect logic take over). Used by cloudlink's failure
// cascade after repeated socket-level failures.
void kp_net_reset(void);

#ifdef __cplusplus
}
#endif
