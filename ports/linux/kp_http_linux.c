// Small buffered HTTP requests over libcurl (OTA manifest checks and status
// reports). The body is truncated to the caller's buffer, as on every port.

#include "koios/port/kp_http.h"
#include "koios/port/kp_log.h"
#include "kp_linux.h"

#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* TAG = "kp_http";

#define REQUEST_TIMEOUT_S 20L

typedef struct {
    char* buf;
    size_t size;
    size_t len;
} sink_t;

static pthread_once_t s_curl_once = PTHREAD_ONCE_INIT;

static void curl_init_once(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t on_body(char* data, size_t size, size_t nmemb, void* user) {
    sink_t* sink = user;
    const size_t n = size * nmemb;
    const size_t room = sink->size - sink->len - 1;
    const size_t take = n < room ? n : room;
    if (take > 0) {
        memcpy(sink->buf + sink->len, data, take);
        sink->len += take;
        sink->buf[sink->len] = '\0';
    }
    return n;  // swallow what does not fit; the transfer still completes
}

static int do_request(const char* url,
    const kp_http_header_t* headers, size_t header_count,
    const char* body,
    char* buf, size_t buf_size,
    int* status_code) {
    if (!url || !buf || buf_size < 2 || !status_code) return -1;
    *status_code = 0;
    buf[0] = '\0';

    pthread_once(&s_curl_once, curl_init_once);
    CURL* curl = curl_easy_init();
    if (!curl) return -1;

    sink_t sink = { .buf = buf, .size = buf_size, .len = 0 };
    struct curl_slist* list = NULL;
    for (size_t i = 0; i < header_count; i++) {
        if (!headers[i].key || !headers[i].value) continue;
        const size_t n = strlen(headers[i].key) + strlen(headers[i].value) + 3;
        char* line = malloc(n);
        if (!line) continue;
        snprintf(line, n, "%s: %s", headers[i].key, headers[i].value);
        list = curl_slist_append(list, line);
        free(line);
    }
    if (body) list = curl_slist_append(list, "Content-Type: application/json");

    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TIMEOUT_S);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "koios-sdk-linux");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    if (cfg->ca_file) curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->ca_file);
    if (body) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }

    const CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    *status_code = (int)status;
    if (rc != CURLE_OK) KP_LOGD(TAG, "%s: %s", url, curl_easy_strerror(rc));

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK ? 0 : -1;
}

int kp_http_get(const char* url,
    const kp_http_header_t* headers, size_t header_count,
    char* buf, size_t buf_size,
    int* status_code) {
    return do_request(url, headers, header_count, NULL, buf, buf_size, status_code);
}

int kp_http_post_json(const char* url,
    const kp_http_header_t* headers, size_t header_count,
    const char* body,
    char* buf, size_t buf_size,
    int* status_code) {
    if (!body) return -1;
    return do_request(url, headers, header_count, body, buf, buf_size, status_code);
}
