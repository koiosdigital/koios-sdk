# koios-sdk

Device-side SDK for the Koios cloud: the persistent WebSocket link
(**cloudlink**) and firmware **OTA** update policy, written as portable C
over a small **ports** layer.

```
include/koios/          public API
  cloudlink.h             device <-> cloud WebSocket session
  ota.h                   update-check protocol + scheduling
  port/                   the port contracts (kp_*)
core/                   portable core — no platform includes (cJSON only)
ports/esp-idf/          ESP-IDF port, layered on kd_common
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
| `kp_ota` | download & flash an image | esp_https_ota |

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

kd_common_init();

koios_ota_init(NULL);  // defaults: firmware.api.koiosdigital.net, no variant

koios_cloudlink_config_t link = {
    .url = "wss://vn-sec.koios.sh",
    .auth_mode = KOIOS_CLOUD_AUTH_MTLS,
    .on_message = my_protobuf_dispatch,   // binary frames are yours
    .on_session_ready = my_hello,         // send device info, claims, ...
};
koios_cloudlink_init(&link);
```

Text frames are the shared control channel (`welcome` / `token` /
`twin.*`) and are handled inside cloudlink; binary frames are the
app-specific protocol (protobuf in current firmwares) and pass through
untouched.

## Porting

Implement the nine `kp_*` headers under `include/koios/port/` for the new
platform and compile `core/` with them. The core has no RTOS, socket, or
TLS assumptions beyond those contracts; cJSON is its only library
dependency.
