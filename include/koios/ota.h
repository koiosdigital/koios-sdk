#pragma once

// Firmware updates against the Koios OTA service (ota.api.koios.sh).
//
// Protocol (device plane, authenticated with the cloudlink device JWT):
//   GET  /v1/ota/check                   204 = up to date, 200 = offer:
//        { "data": { "manifest": { "update_id", "version",
//                                  "artifact": { "url", "size", "sha256" } },
//                    "signed": "<ES256 compact JWS of the manifest>" } }
//   GET  <artifact.url>                  the image (Bearer, Range-resumable)
//   POST /v1/ota/updates/<id>/status     { "status", "error_code"? }
//
// The device downloads over pinned TLS, verifies the image sha256 against
// the manifest before the new boot partition is committed, reports
// `rebooting`, restarts, and confirms (`confirmed` / `rolled_back`) on the
// next boot via the update id persisted through the kp_ota port.
// TODO: additionally verify the manifest JWS against the service JWKS
// (defense in depth beyond TLS; needs an ES256 verify port).
//
// Policy (unchanged): first check ~30 s after the cloud session is ready
// (letting the post-IP rush settle), up to 3 boot-check retries, then a
// 12 h periodic timer. A server `ota.offer` push frame triggers an
// immediate check. The download/flash itself is the kp_ota port.

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // NULL -> https://ota.api.koios.sh
    const char* endpoint_url;
} koios_ota_config_t;

// Register for network events and start the check schedule. config may be
// NULL for defaults. Call once, after koios_cloudlink_init() — checks need
// the device JWT the cloud session carries.
void koios_ota_init(const koios_ota_config_t* config);

// True once the boot-time check has concluded (success or gave up).
bool koios_ota_boot_check_completed(void);

// Trigger an immediate check (no-op if one is already running or offline).
// Called internally when the server pushes an `ota.offer` frame.
void koios_ota_check_now(void);

#ifdef __cplusplus
}
#endif
