# koios-sdk

Device-side SDK for the Koios cloud: the persistent WebSocket link
(**cloudlink**), firmware **OTA** update policy, **log shipping** and
**metrics**, written as portable C over a small **ports** layer. Ports:
ESP-IDF and Linux.

```
include/koios/          public API
  cloudlink.h             device <-> cloud WebSocket session
  ota.h                   update-check protocol + scheduling
  logship.h               log shipping
  metrics.h               device metrics
  port/                   the port contracts (kp_*)
core/                   portable core — no platform includes (cJSON only)
ports/esp-idf/          ESP-IDF port, layered on kd_common
ports/linux/            Linux port (pthreads, OpenSSL 3, libcurl), the
                        koios-agent daemon and the tests: docs/linux.md
```

## Architecture

The core owns *policy*: connection state machine, jittered exponential
backoff, welcome/session handling, device-JWT lifecycle, failure escalation
(socket → network reset → restart), OTA manifest protocol and check
scheduling. Ports own *mechanism*: TLS websockets, HTTP, flash/apply,
identity, RTOS primitives.

| Port | Contract | ESP-IDF implementation |
|---|---|---|
| `kp_os` | mutex/sem/task/timer/alloc/time | FreeRTOS + esp_timer; SPIRAM alloc per Kconfig |
| `kp_log` | leveled logging | esp_log |
| `kp_net` | connectivity events + reset | esp_event (WIFI/IP events) + kd_common WiFi |
| `kp_http` | small buffered GET | kd_common's shared serialized HTTP client |
| `kp_identity` | client cert + opaque key handle | kd_common crypto (DS peripheral) |
| `kp_websocket` | complete-message WS client | esp_websocket_client + cert bundle |
| `kp_ota` | download/verify/flash an image + pending-update record | esp_https_ota (streamed sha256) + NVS |
| `kp_logstore` | reset-surviving leveled-log capture + ring | esp_log_set_vprintf hook + RTC_NOINIT ring |
| `kp_metrics` | one sample of the system's vital signs | heap, tasks, uptime, RSSI, reset reason; CPU with run-time stats |

The Linux implementations are listed in [docs/linux.md](docs/linux.md).

The private key never crosses the port boundary: `kp_identity` hands out an
opaque context (`esp_ds_data_ctx_t*` on ESP32) that `kp_websocket` feeds to
esp-tls for hardware-backed mTLS.

## Auth modes

- `KOIOS_CLOUD_AUTH_MTLS` — `wss://vn-sec.koios.sh`, edge-validated client
  certificate. Cloudlink waits for `kp_identity_ready()` before connecting.
- `KOIOS_CLOUD_AUTH_API_KEY` — `wss://vn.koios.sh`,
  `Authorization: Bearer <device or provisioning key>` on the handshake.
  If the server autocreates the device it mints a device key, delivered
  once in the welcome frame (`on_api_key_issued` — persist it).

## Usage (ESP-IDF)

Add as a git submodule at `components/koios_sdk` next to `kd_common`,
then:

```c
#include <koios/cloudlink.h>
#include <koios/ota.h>
#include <koios/logship.h>

kd_common_init();

koios_ota_init(NULL);  // defaults: https://ota.api.koios.sh (Koios OTA service)

koios_cloudlink_config_t link = {
    .url = "wss://vn-sec.koios.sh",
    .auth_mode = KOIOS_CLOUD_AUTH_MTLS,
    .on_message = my_protobuf_dispatch,   // binary frames are yours
    .on_session_ready = my_hello,         // send device info, claims, ...
};
koios_cloudlink_init(&link);

koios_logship_init(NULL);   // opt-in (Kconfig); off unless enabled
```

Text frames are the shared control channel (`welcome` / `token` /
`twin.*`) and are handled inside cloudlink; binary frames are the
app-specific protocol (protobuf in current firmwares) and pass through
untouched.

## Log shipping

`koios_logship_init()` hooks the ESP-IDF logger (`esp_log_set_vprintf`) and
captures every `ESP_LOGx` line — level, tag, message, and a wall-clock
timestamp — into a **byte-sized ring in RTC-retained memory** (2 KiB by
default), so the lines written just before a reset, brownout, or deep sleep
survive it. The ring is sized in bytes, not lines: variable-length records pack
in and the oldest are evicted when it fills.

While the cloudlink session is up, lines **ship as they arrive** — capture nudges
the ship task per line, which forwards them straight away as a text control
frame over the **existing cloudlink websocket**:

```json
{"type":"logs","logs":[{"level":"info","tag":"wifi","message":"...","ts":1699999999000}, ...]}
```

Because the frame rides the already-authenticated device session, the gateway
stamps the connection's `device_id`/`fleet_id`/`tenant_id` onto every line — so
there is **no separate log host, no bearer token, and no `logs.write`
capability** to provision per fleet. This works the same for mTLS and API-key
devices (the socket is the device's one authenticated channel). When the link is
down, lines accumulate in the ring and flush once the session is ready (the ship
task polls readiness so the reset-survived tail goes out promptly). Lines
captured before the clock syncs ship without a timestamp and the gateway stamps
them at receive time.

The feature is **opt-in and off by default**, gated by
`CONFIG_KOIOS_SDK_LOGS_ENABLE` (mirroring how the app opts into OTA). When
disabled, `koios_logship_init()` is a no-op and the component adds no capture
hook, task, or RTC footprint. Ring byte size, tag/message caps, the
retry/fallback interval, and max frame body are Kconfig options.

Crash scope: RTC survival of the pre-reboot log tail is what this provides.
Coredump capture (`esp_core_dump`) is a possible later add and is out of scope.

## Metrics

`koios_metrics_init()` samples the platform every interval (60 s by default)
and sends the samples as a text control frame on the cloudlink websocket:

```json
{"type":"metrics","samples":[{"uptime_s":86400,"ts":1731790000000,"cpu_pct":12.5,
  "mem_total_bytes":8322359296,"mem_free_bytes":7475027968,"tasks":212}]}
```

One schema serves every port; a field is present when the platform has it
(`include/koios/port/kp_metrics.h`). An ESP32 sends heap figures
(`mem_*`, `mem_min_free_bytes`, `mem_largest_block_bytes`,
`mem_internal_free_bytes` with PSRAM), `tasks`, `net_rssi_dbm`, `cpu_cores`,
`cpu_pct` when FreeRTOS run-time statistics are on, and `reset_reason` once
per boot. An application adds its own values with
`koios_metrics_gauge("name", value)`; they travel as `x_<name>`.

While the session is down the newest samples wait in RAM and go out in one
frame afterwards. The cloud changes the interval through the twin:
`desired.koios.metrics.interval_s` (0 stops reporting). The gateway takes the
frame from devices whose token has `telemetry.write`, which is in the
platform's default set.

**Opt-in and off by default** on ESP-IDF, gated by
`CONFIG_KOIOS_SDK_METRICS_ENABLE`; when disabled `koios_metrics_init()` is a
no-op and nothing is added.

## Porting

Implement the `kp_*` port headers under `include/koios/port/` for the new
platform and compile `core/` with them. The core has no RTOS, socket, or
TLS assumptions beyond those contracts; cJSON is its only library
dependency. `ports/linux` is the second port and the one to read first: it
has no vendor layer under it.
