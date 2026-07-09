#pragma once

// Firmware update checks against the Koios firmware API.
//
// Protocol: GET <endpoint> with x-firmware-project / x-firmware-version
// (/ x-firmware-variant) headers; response
//   { "update_available": bool, "ota_url": "https://..." }
//
// Policy (unchanged from kd_common): first check ~30 s after network comes
// up (letting the post-IP rush settle), up to 3 boot-check retries, then a
// 12 h periodic timer. The download/flash itself is the kp_ota port.

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // NULL -> https://firmware.api.koiosdigital.net
    const char* endpoint_url;
    // Optional x-firmware-variant header value. NULL to omit.
    const char* variant;
} koios_ota_config_t;

// Register for network events and start the check schedule. config may be
// NULL for defaults. Call once, after the platform net layer is initialized.
void koios_ota_init(const koios_ota_config_t* config);

// True once the boot-time check has concluded (success or gave up).
bool koios_ota_boot_check_completed(void);

// Trigger an immediate check (no-op if one is already running or offline).
void koios_ota_check_now(void);

#ifdef __cplusplus
}
#endif
