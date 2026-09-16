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
// next boot via the update id persisted through the kp_ota port. A failed
// download/verify/flash is reported as `failed` with an error code.
// TODO: additionally verify the manifest JWS against the service JWKS
// (defense in depth beyond TLS; needs an ES256 verify port).
//
// Policy: the boot check runs ~10 s after cloudlink reports the cloud
// session ready (the check needs the device JWT that session carries, and
// by then the post-IP rush — SNTP, mDNS, the WS TLS handshake — has
// settled). A failed boot check is retried 60 s later, up to 3 attempts;
// then a 12 h periodic timer takes over. A server `ota.offer` push frame
// triggers an immediate check. The download/flash itself is the kp_ota port.

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // NULL -> https://ota.api.koios.sh
    const char* endpoint_url;
} koios_ota_config_t;

// Start the check schedule. config may be NULL for defaults. Call once,
// after koios_cloudlink_init() — checks need the device JWT the cloud
// session carries and are triggered by its session-ready event.
void koios_ota_init(const koios_ota_config_t* config);

// True once the boot-time check has concluded (success or gave up).
bool koios_ota_boot_check_completed(void);

// Trigger an immediate check (no-op if one is already running or offline).
// Called internally when the server pushes an `ota.offer` frame.
void koios_ota_check_now(void);

// Called by cloudlink when the cloud session becomes ready. Arms the boot
// check (once per boot, with a short settle delay). No-op before
// koios_ota_init() or once the boot check has concluded. Never blocks.
void koios_ota_on_session_ready(void);

#ifdef __cplusplus
}
#endif
