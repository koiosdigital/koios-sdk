#pragma once

// Firmware update application port. The core decides *when* and *what* to
// update (manifest protocol, scheduling, status reporting); the port knows
// *how* to download-verify-flash an image on its platform.

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// kp_ota_download_and_apply() results. Nonzero leaves the running image
// untouched; the core maps these onto status-report error codes.
#define KP_OTA_OK           0
#define KP_OTA_ERR_DOWNLOAD (-1)  // transport / HTTP error
#define KP_OTA_ERR_FLASH    (-2)  // write / partition / image-format error
#define KP_OTA_ERR_HASH     (-3)  // image sha256 != expected

typedef struct {
    const char* url;         // image URL
    const char* bearer;      // Authorization: Bearer value, or NULL
    const char* sha256_hex;  // expected image sha256 (lowercase hex), or NULL to skip
    size_t size;             // expected size in bytes, 0 to skip the check
} kp_ota_image_t;

// Download, verify and flash the image, and mark it for the next boot —
// WITHOUT restarting (the core reports `rebooting` first, then calls
// kp_ota_restart). Blocking. The expected sha256 must be checked before the
// new image is committed as the boot target.
int kp_ota_download_and_apply(const kp_ota_image_t* image);

// Restart into the newly applied image. Does not return.
void kp_ota_restart(void);

// Identity of the running firmware.
void kp_ota_get_app_desc(char* project, size_t project_size,
                         char* version, size_t version_size);

// Persist / recall the update the device is rebooting into, so the core can
// report `confirmed` or `rolled_back` on the next boot. Load returns 0 when
// a pending record exists.
int kp_ota_pending_save(const char* update_id, const char* version);
int kp_ota_pending_load(char* update_id, size_t id_size,
                        char* version, size_t version_size);
void kp_ota_pending_clear(void);

#ifdef __cplusplus
}
#endif
