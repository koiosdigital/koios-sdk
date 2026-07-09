#pragma once

// Firmware update application port. The core decides *when* and *what* to
// update (manifest protocol, scheduling, retries); the port knows *how* to
// flash an image on its platform.

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Download the image at url and apply it. Blocking. On success the port
// restarts the device and this call never returns; nonzero means the update
// failed and the running image is untouched.
int kp_ota_download_and_apply(const char* url);

// Identity of the running firmware, used for update-check headers.
void kp_ota_get_app_desc(char* project, size_t project_size,
                         char* version, size_t version_size);

#ifdef __cplusplus
}
#endif
