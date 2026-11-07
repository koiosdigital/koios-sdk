#pragma once

// Log shipping: capture every leveled log line, buffer it in reset-surviving
// storage, and stream batches to the Koios gateway's log ingest endpoint
// (POST /v1/logs) authenticated with the cloudlink device JWT.
//
// Opt-in and off by default, gated by CONFIG_KOIOS_SDK_LOGS_ENABLE (mirrors
// how OTA is wired in: the app calls the init, a Kconfig switch decides whether
// anything runs). When disabled, koios_logship_init() is a no-op and the
// component adds no capture hook, task, or retained-memory footprint.
//
// Capture starts at init so boot-time lines are recorded; the background ship
// task waits for connectivity and a device token before it starts forwarding.
// Lines buffered before a reset survive it and ship once the device is back
// online, so the log tail leading up to a crash is not lost.
//
// NOTE: the device JWT must carry the `logs.write` capability, which a device
// only receives if its fleet includes `logs.write` in `default_caps`. Without
// it the gateway answers 403 and the ship task logs a warning and backs off.

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Ingest endpoint. NULL -> https://vn.koios.sh/v1/logs. The JWT auth path
    // is host-agnostic, so this stays on the plain vn ingress even for mTLS
    // devices (like OTA's https endpoint), rather than vn-sec.koios.sh.
    const char* ingest_url;

    // Flush cadence in milliseconds. 0 -> the Kconfig default. The task also
    // flushes early on an error-level line, a full buffer, or network-up.
    uint32_t flush_interval_ms;
} koios_logship_config_t;

// Install capture and start the ship task. Call after koios_cloudlink_init()
// (the ship task reuses the cloudlink device token). Pass NULL for defaults.
void koios_logship_init(const koios_logship_config_t* config);

// Request a flush as soon as the ship task can run (network + token allowing).
// No-op when log shipping is disabled or not initialized.
void koios_logship_flush(void);

#ifdef __cplusplus
}
#endif
