#pragma once

// Log shipping: capture every leveled log line, buffer it in reset-surviving
// storage, and stream batches to the Koios cloud over the **existing cloudlink
// websocket** — a `{"type":"logs","logs":[...]}` control frame the gateway
// ingests under the connection's already-authenticated device identity. No
// separate log host, no bearer token, and no `logs.write` capability: being
// connected is the authorization, so nothing has to be granted per fleet.
//
// Opt-in and off by default, gated by CONFIG_KOIOS_SDK_LOGS_ENABLE (mirrors
// how OTA is wired in: the app calls the init, a Kconfig switch decides whether
// anything runs). When disabled, koios_logship_init() is a no-op and the
// component adds no capture hook, task, or retained-memory footprint.
//
// Capture starts at init so boot-time lines are recorded; the background ship
// task waits until the cloudlink session is ready, then forwards. Lines
// buffered before a reset survive it (RTC-retained ring) and ship once the
// session is back, so the log tail leading up to a crash is not lost.

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Flush cadence in milliseconds. 0 -> the Kconfig default. The task also
    // flushes early on an error-level line, a full buffer, and network-up.
    uint32_t flush_interval_ms;
} koios_logship_config_t;

// Install capture and start the ship task. Call after koios_cloudlink_init()
// (the ship task rides the cloudlink websocket). Pass NULL for defaults.
void koios_logship_init(const koios_logship_config_t* config);

// Request a flush as soon as the ship task can run (session-ready permitting).
// No-op when log shipping is disabled or not initialized.
void koios_logship_flush(void);

#ifdef __cplusplus
}
#endif
