// Updates on Linux: this port never writes a partition or replaces a file of
// the system. It downloads the image into a staging directory, checks its
// size and SHA-256, and hands the file to an installer the system provides
// (ota_apply_cmd): a package manager, swupdate, an A/B updater. The installer
// owns verification of the image's signature and the way back if it does not
// boot. Without an installer configured every update is refused.

#include "koios/port/kp_ota.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "kp_linux.h"

#include <curl/curl.h>
#include <openssl/evp.h>

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

static const char* TAG = "kp_ota";

#define DOWNLOAD_RESUME_ATTEMPTS 5
#define APPLY_TIMEOUT_S          (30 * 60)
#define MAX_ARGS                 24

//------------------------------------------------------------------------------
// Paths
//------------------------------------------------------------------------------

static bool staging_dir(char* out, size_t out_size) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    int n;
    if (cfg->ota_staging_dir) n = snprintf(out, out_size, "%s", cfg->ota_staging_dir);
    else if (cfg->state_dir) n = snprintf(out, out_size, "%s/ota", cfg->state_dir);
    else return false;
    return n > 0 && (size_t)n < out_size && kp_linux_mkdirs(out, 0750) == 0;
}

static bool pending_path(char* out, size_t out_size) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (!cfg->state_dir) return false;
    return snprintf(out, out_size, "%s/ota_pending", cfg->state_dir) < (int)out_size;
}

//------------------------------------------------------------------------------
// Download
//------------------------------------------------------------------------------

static size_t on_data(char* data, size_t size, size_t nmemb, void* user) {
    return fwrite(data, size, nmemb, (FILE*)user) * size;
}

// Fetch url into path, continuing a partial file after a dropped transfer.
static int download(const kp_ota_image_t* image, const char* path) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    remove(path);

    for (int attempt = 1; attempt <= DOWNLOAD_RESUME_ATTEMPTS; attempt++) {
        FILE* f = fopen(path, "ab");
        if (!f) {
            KP_LOGE(TAG, "cannot write %s: %s", path, strerror(errno));
            return KP_OTA_ERR_FLASH;
        }
        const long have = ftell(f);

        CURL* curl = curl_easy_init();
        if (!curl) {
            fclose(f);
            return KP_OTA_ERR_DOWNLOAD;
        }
        curl_easy_setopt(curl, CURLOPT_URL, image->url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
        // No overall timeout (images are large); give up on a stalled transfer.
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "koios-sdk-linux");
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https,http");
        if (cfg->ca_file) curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->ca_file);
        if (image->bearer) {
            // As an auth credential, not a header: libcurl then keeps the
            // token to the host it was meant for across redirects.
            const char* token = image->bearer;
            if (strncmp(token, "Bearer ", 7) == 0) token += 7;
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BEARER);
            curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token);
        }
        if (have > 0) curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)have);

        const CURLcode rc = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        curl_easy_cleanup(curl);
        const bool wrote = fclose(f) == 0;

        if (rc == CURLE_OK && wrote) return KP_OTA_OK;
        if (rc == CURLE_WRITE_ERROR || !wrote) {
            KP_LOGE(TAG, "writing the image failed (disk full?)");
            return KP_OTA_ERR_FLASH;
        }
        KP_LOGW(TAG, "download attempt %d/%d: %s (http %ld)", attempt, DOWNLOAD_RESUME_ATTEMPTS,
            curl_easy_strerror(rc), status);
        // An HTTP error is the server's answer; only a broken transfer is worth resuming.
        if (rc == CURLE_HTTP_RETURNED_ERROR || rc == CURLE_RANGE_ERROR) break;
        kp_delay_ms(2000);
    }
    return KP_OTA_ERR_DOWNLOAD;
}

static bool sha256_file(const char* path, char hex[65], size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
    unsigned char buf[64 * 1024];
    size_t n, total = 0;
    while (ok && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ok = EVP_DigestUpdate(md, buf, n) == 1;
        total += n;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    ok = ok && !ferror(f) && EVP_DigestFinal_ex(md, digest, &len) == 1 && len == 32;
    EVP_MD_CTX_free(md);
    fclose(f);
    if (!ok) return false;
    for (unsigned i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    *size = total;
    return true;
}

//------------------------------------------------------------------------------
// The installer
//------------------------------------------------------------------------------

// Run cmd (split on blanks, no shell) with extra arguments appended. Returns
// the exit status, or -1 when it could not be run, was killed or timed out.
static int run_cmd(const char* cmd, const char* const* extra, int timeout_s) {
    char* copy = strdup(cmd);
    if (!copy) return -1;
    char* argv[MAX_ARGS + 1];
    int argc = 0;
    char* save = NULL;
    for (char* tok = strtok_r(copy, " \t", &save); tok && argc < MAX_ARGS; tok = strtok_r(NULL, " \t", &save)) {
        argv[argc++] = tok;
    }
    for (int i = 0; extra && extra[i] && argc < MAX_ARGS; i++) argv[argc++] = (char*)extra[i];
    argv[argc] = NULL;
    if (argc == 0) {
        free(copy);
        return -1;
    }

    pid_t pid;
    const int rc = posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
    free(copy);
    if (rc != 0) {
        KP_LOGE(TAG, "cannot run %s: %s", cmd, strerror(rc));
        return -1;
    }

    const int64_t deadline = kp_monotonic_us() + (int64_t)timeout_s * 1000000;
    for (;;) {
        int status;
        const pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) {
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        if (done < 0 && errno != EINTR) return -1;
        if (kp_monotonic_us() > deadline) {
            KP_LOGE(TAG, "%s did not finish within %d s, stopping it", cmd, timeout_s);
            kill(pid, SIGTERM);
            kp_delay_ms(2000);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -1;
        }
        kp_delay_ms(200);
    }
}

int kp_ota_download_and_apply(const kp_ota_image_t* image) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (!image || !image->url) return KP_OTA_ERR_DOWNLOAD;
    if (!cfg->ota_apply_cmd) {
        KP_LOGE(TAG, "no installer is configured (ota_apply_cmd): this device takes no updates from here");
        return KP_OTA_ERR_FLASH;
    }

    char dir[480], path[512];
    if (!staging_dir(dir, sizeof(dir))) {
        KP_LOGE(TAG, "no staging directory for the download");
        return KP_OTA_ERR_FLASH;
    }
    snprintf(path, sizeof(path), "%s/update.img", dir);

    int rc = download(image, path);
    if (rc != KP_OTA_OK) {
        remove(path);
        return rc;
    }

    char hex[65];
    size_t size = 0;
    if (!sha256_file(path, hex, &size)) {
        remove(path);
        return KP_OTA_ERR_FLASH;
    }
    if (image->size && size != image->size) {
        KP_LOGE(TAG, "image is %zu bytes, the offer said %zu", size, image->size);
        remove(path);
        return KP_OTA_ERR_HASH;
    }
    if (image->sha256_hex && strcasecmp(hex, image->sha256_hex) != 0) {
        KP_LOGE(TAG, "image sha256 does not match the offer");
        remove(path);
        return KP_OTA_ERR_HASH;
    }

    KP_LOGI(TAG, "image verified (%zu bytes), handing it to the installer", size);
    const char* extra[] = {
        path,
        image->version ? image->version : "",
        image->update_id ? image->update_id : "",
        NULL,
    };
    const int status = run_cmd(cfg->ota_apply_cmd, extra, APPLY_TIMEOUT_S);
    remove(path);
    if (status != 0) {
        KP_LOGE(TAG, "the installer refused the image (status %d)", status);
        return KP_OTA_ERR_FLASH;
    }
    return KP_OTA_OK;
}

void kp_ota_restart(void) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (cfg->ota_restart_cmd) {
        KP_LOGI(TAG, "restarting into the update: %s", cfg->ota_restart_cmd);
        run_cmd(cfg->ota_restart_cmd, NULL, 120);
        // A reboot takes a moment to take this process down.
        kp_delay_ms(60000);
    }
    kp_system_restart();
    for (;;) kp_delay_ms(1000);
}

//------------------------------------------------------------------------------
// What runs, and what was being installed
//------------------------------------------------------------------------------

void kp_ota_get_app_desc(char* project, size_t project_size,
    char* version, size_t version_size) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (project && project_size) snprintf(project, project_size, "%s", cfg->project ? cfg->project : "");
    if (version && version_size) snprintf(version, version_size, "%s", cfg->version ? cfg->version : "");
}

const char* kp_ota_get_device_class(void) {
    return kp_linux_cfg()->device_class;
}

int kp_ota_pending_save(const char* update_id, const char* version) {
    char path[560], tmp[580];
    if (!update_id || !version || !pending_path(path, sizeof(path))) return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* f = fopen(tmp, "w");
    if (!f) return -1;
    const bool ok = fprintf(f, "%s\n%s\n", update_id, version) > 0;
    if (fclose(f) != 0 || !ok || rename(tmp, path) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}

int kp_ota_pending_load(char* update_id, size_t id_size, char* version, size_t version_size) {
    char path[560];
    if (!pending_path(path, sizeof(path))) return -1;
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char id[128] = "", ver[128] = "";
    const bool ok = fgets(id, sizeof(id), f) && fgets(ver, sizeof(ver), f);
    fclose(f);
    if (!ok) return -1;
    id[strcspn(id, "\r\n")] = '\0';
    ver[strcspn(ver, "\r\n")] = '\0';
    if (!id[0] || !ver[0]) return -1;
    if (update_id && id_size) snprintf(update_id, id_size, "%s", id);
    if (version && version_size) snprintf(version, version_size, "%s", ver);
    return 0;
}

void kp_ota_pending_clear(void) {
    char path[560];
    if (pending_path(path, sizeof(path))) remove(path);
}
