#pragma once

// Device metrics: a periodic sample of the system's vital signs (CPU, memory,
// storage, temperature, network, tasks), reported to the Koios cloud over the
// existing cloudlink websocket as a text control frame:
//
//   {"type":"metrics","samples":[{"ts":1731790000000,"uptime_s":86400,
//     "cpu_pct":12.5,"mem_total_bytes":...,"mem_free_bytes":...,...}]}
//
// One schema serves every port. A field is present when the platform has it
// (see port/kp_metrics.h): a Linux box sends CPU, memory, storage,
// temperature and network counters; an ESP32 sends heap figures, task count,
// signal strength and, once per boot, the reset reason. `ts` is the wall
// clock in milliseconds and is left out until the clock is set; the gateway
// then stamps the time of arrival.
//
// The frame rides the device's authenticated session. The gateway accepts it
// from devices whose token carries the `telemetry.write` capability, which
// is in the platform's default set.
//
// While the session is down the newest samples wait in memory and go out in
// one frame when it is back. The interval can be changed from the cloud
// through the device twin: desired.koios.metrics.interval_s (0 stops
// reporting, the SDK clamps other values to 10..3600).
//
// Opt-in, like log shipping: nothing runs unless the build defines
// CONFIG_KOIOS_SDK_METRICS_ENABLE; koios_metrics_init() is then a no-op.

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Seconds between samples. 0 -> the build's default (60).
    uint32_t interval_s;
    // Samples kept while the session is down. 0 -> the build's default.
    uint16_t backlog;
} koios_metrics_config_t;

// Start sampling and reporting. Call after koios_cloudlink_init(). Pass NULL
// for defaults.
void koios_metrics_init(const koios_metrics_config_t* config);

// Change the interval at run time (what a desired-twin change does). 0 stops
// reporting until a nonzero interval is set again.
void koios_metrics_set_interval(uint32_t seconds);

// Publish an application value with every following sample, as "x_<name>".
// name: 1..15 characters of [a-z0-9_]. Setting it again replaces the value;
// koios_metrics_gauge_clear() removes it. At most 8 gauges. False when the
// name is invalid, the table is full, or metrics are not enabled.
bool koios_metrics_gauge(const char* name, double value);
void koios_metrics_gauge_clear(const char* name);

// Take a sample now and send it as soon as the session allows.
void koios_metrics_report_now(void);

// Called by cloudlink with the `desired` object of a twin.desired frame.
// Applies desired.koios.metrics.interval_s when it is there. No-op before
// koios_metrics_init().
struct cJSON;
void koios_metrics_on_twin_desired(const struct cJSON* desired);

#ifdef __cplusplus
}
#endif
