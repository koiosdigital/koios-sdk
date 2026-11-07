// Log shipping policy (portable).
//
// Drains the reset-surviving log store (kp_logstore) and streams batches as
// NDJSON to the Koios gateway's POST /v1/logs, authenticated with the cloudlink
// device JWT — the same token OTA uses. Mechanism (capture, retained storage,
// HTTP, RTOS) lives behind the kp_* ports; this file owns only policy: when to
// flush, how to batch, how to serialize, and how to react to the gateway.
//
// The whole module is compiled out unless CONFIG_KOIOS_SDK_LOGS_ENABLE is set,
// mirroring how OTA is an opt-in the app wires in. koios_logship_init() is
// always defined so callers link unconditionally; it is a no-op when disabled.

#include "koios/logship.h"

#include "koios/port/kp_log.h"

#if defined(CONFIG_KOIOS_SDK_LOGS_ENABLE)

#include "koios/cloudlink.h"
#include "koios/port/kp_logstore.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_net.h"
#include "koios/port/kp_http.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char* TAG = "koios_logship";

#define DEFAULT_INGEST_URL "https://vn.koios.sh/v1/logs"

#ifdef CONFIG_KOIOS_SDK_LOGS_FLUSH_INTERVAL_MS
#define DEFAULT_FLUSH_INTERVAL_MS CONFIG_KOIOS_SDK_LOGS_FLUSH_INTERVAL_MS
#else
#define DEFAULT_FLUSH_INTERVAL_MS 60000
#endif

#ifdef CONFIG_KOIOS_SDK_LOGS_BODY_BYTES
#define BODY_CAP CONFIG_KOIOS_SDK_LOGS_BODY_BYTES
#else
#define BODY_CAP 16384
#endif

// Covers the TLS POST path plus the NDJSON assembly scratch on the frame.
#define SHIP_TASK_STACK_BYTES 10240
#define SHIP_TASK_PRIORITY    4
// Small: the gateway only returns {data:{accepted,rejected}}.
#define RESPONSE_BUFFER_SIZE  192

static struct {
    koios_logship_config_t cfg;
    uint32_t flush_interval_ms;
    kp_sem_t wake;
    koios_log_entry_t* batch;   // peek scratch, capacity entries
    size_t batch_cap;
    char* body;                 // NDJSON assembly buffer, BODY_CAP bytes
    bool running;
} s;

//------------------------------------------------------------------------------
// Serialization
//------------------------------------------------------------------------------

static const char* level_name(uint8_t level) {
    switch (level) {
    case KOIOS_LOG_ERROR:   return "error";
    case KOIOS_LOG_WARN:    return "warn";
    case KOIOS_LOG_INFO:    return "info";
    case KOIOS_LOG_DEBUG:   return "debug";
    case KOIOS_LOG_VERBOSE: return "verbose";
    default:                return "info";
    }
}

// Escape src into dst (no surrounding quotes), NUL-terminated, truncated to
// fit dst_cap. Returns dst.
static char* json_escape(char* dst, size_t dst_cap, const char* src) {
    size_t w = 0;
    for (const char* p = src; *p && w + 7 < dst_cap; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            dst[w++] = '\\';
            dst[w++] = (char)c;
        } else if (c < 0x20) {
            w += (size_t)snprintf(dst + w, dst_cap - w, "\\u%04x", c);
        } else {
            dst[w++] = (char)c;
        }
    }
    dst[w] = '\0';
    return dst;
}

// Render one record as a JSON object (no trailing newline) into out. Returns
// the length, or 0 if it would not fit.
static size_t render_record(char* out, size_t out_cap, uint8_t level,
    const char* tag, const char* message, int64_t ts_ms) {
    char etag[KOIOS_LOG_TAG_LEN * 2 + 2];
    char emsg[KOIOS_LOG_MSG_LEN * 6 + 8];
    json_escape(etag, sizeof(etag), tag ? tag : "");
    json_escape(emsg, sizeof(emsg), message ? message : "");

    int n;
    if (ts_ms > 0) {
        n = snprintf(out, out_cap,
            "{\"level\":\"%s\",\"tag\":\"%s\",\"message\":\"%s\",\"ts\":%lld}",
            level_name(level), etag, emsg, (long long)ts_ms);
    } else {
        n = snprintf(out, out_cap,
            "{\"level\":\"%s\",\"tag\":\"%s\",\"message\":\"%s\"}",
            level_name(level), etag, emsg);
    }
    if (n < 0 || (size_t)n >= out_cap) return 0;
    return (size_t)n;
}

//------------------------------------------------------------------------------
// Ship
//------------------------------------------------------------------------------

typedef enum { POST_OK, POST_AUTH, POST_FAIL } post_result_t;

static post_result_t post_batch(const char* token, const char* body, size_t body_len) {
    (void)body_len;
    char* auth = kp_malloc(strlen(token) + 8);
    if (!auth) return POST_FAIL;
    sprintf(auth, "Bearer %s", token);
    kp_http_header_t headers[1] = { { "Authorization", auth } };

    char response[RESPONSE_BUFFER_SIZE];
    int status = 0;
    int err = kp_http_post(s.cfg.ingest_url, headers, 1, body,
        "application/x-ndjson", response, sizeof(response), &status);
    kp_free(auth);

    if (err != 0) return POST_FAIL;
    if (status >= 200 && status < 300) return POST_OK;
    if (status == 401 || status == 403) {
        KP_LOGW(TAG, "Log ingest rejected (%d) — token missing 'logs.write'? "
            "fleet default_caps must include it; requesting refresh", status);
        return POST_AUTH;
    }
    KP_LOGD(TAG, "Log ingest failed (http %d)", status);
    return POST_FAIL;
}

// Drain the store to the gateway. Keeps entries buffered on any failure so the
// next flush retries them.
static void ship_pending(const char* token) {
    uint32_t dropped = kp_logstore_take_dropped();
    bool first = true;

    for (;;) {
        size_t n = kp_logstore_peek(s.batch, s.batch_cap);
        if (n == 0 && !(first && dropped)) break;

        size_t body_len = 0;
        char rec[KOIOS_LOG_TAG_LEN * 2 + KOIOS_LOG_MSG_LEN * 6 + 64];

        // Lead with a gap marker when lines were overwritten before shipping.
        if (first && dropped) {
            char note[96];
            snprintf(note, sizeof(note),
                "dropped %u buffered log line(s) (device buffer overflow)",
                (unsigned)dropped);
            size_t rl = render_record(rec, sizeof(rec), KOIOS_LOG_WARN, TAG, note, 0);
            if (rl && body_len + rl + 1 <= BODY_CAP) {
                memcpy(s.body + body_len, rec, rl);
                body_len += rl;
                s.body[body_len++] = '\n';
            }
        }

        size_t packed = 0;
        for (size_t i = 0; i < n; i++) {
            size_t rl = render_record(rec, sizeof(rec), s.batch[i].level,
                s.batch[i].tag, s.batch[i].msg, s.batch[i].ts_ms);
            if (rl == 0) { packed++; continue; }  // unrenderable; skip but consume
            if (body_len + rl + 1 > BODY_CAP) break;  // batch full, ship what we have
            memcpy(s.body + body_len, rec, rl);
            body_len += rl;
            s.body[body_len++] = '\n';
            packed++;
        }

        if (body_len == 0) {
            // Nothing renderable (pathological oversized records); drop them
            // rather than wedging the buffer, then stop.
            if (packed > 0) kp_logstore_consume(packed);
            break;
        }
        s.body[body_len] = '\0';

        post_result_t r = post_batch(token, s.body, body_len);
        if (r == POST_AUTH) {
            koios_cloudlink_request_token_refresh();
            return;  // retry on the next flush with a fresh token
        }
        if (r == POST_FAIL) return;  // keep entries buffered, retry later

        kp_logstore_consume(packed);
        first = false;
        dropped = 0;
        if (packed < n) continue;  // buffer-capped batch; more remain
        if (n < s.batch_cap) break;  // peeked the whole store
        // n == batch_cap: there may be more; loop again.
    }
}

static void ship_task(void* arg) {
    (void)arg;
    kp_logstore_mark_ship_task();
    KP_LOGI(TAG, "Log shipping active (endpoint: %s, every %ums, buffer %u lines)",
        s.cfg.ingest_url, (unsigned)s.flush_interval_ms,
        (unsigned)kp_logstore_capacity());

    for (;;) {
        kp_sem_take(s.wake, s.flush_interval_ms);

        if (!kp_net_is_connected()) continue;
        if (kp_logstore_pending() == 0) continue;

        char* token = koios_cloudlink_get_token_copy();
        if (!token) continue;  // no session yet; lines wait (and survive resets)
        ship_pending(token);
        kp_free(token);
    }
}

static void wake_ship(void) {
    if (s.wake) kp_sem_give(s.wake);
}

static void on_net_connect(void) {
    // Push the reset-survived tail out promptly, before it ages past the
    // backend's acceptance window.
    wake_ship();
}

void koios_logship_init(const koios_logship_config_t* config) {
    if (s.running) return;
    if (config) s.cfg = *config;
    if (!s.cfg.ingest_url) s.cfg.ingest_url = DEFAULT_INGEST_URL;
    s.flush_interval_ms = s.cfg.flush_interval_ms ? s.cfg.flush_interval_ms
                                                  : DEFAULT_FLUSH_INTERVAL_MS;

    // Capture first so boot lines are recorded even if the rest fails.
    kp_logstore_init();

    s.batch_cap = kp_logstore_capacity();
    s.batch = kp_malloc(s.batch_cap * sizeof(koios_log_entry_t));
    s.body = kp_malloc(BODY_CAP + 1);  // +1 for the NUL after a full body
    s.wake = kp_sem_create();
    if (!s.batch || !s.body || !s.wake) {
        KP_LOGE(TAG, "Failed to allocate ship buffers; capture only");
        kp_free(s.batch); s.batch = NULL;
        kp_free(s.body);  s.body = NULL;
        return;
    }

    kp_logstore_set_notify(wake_ship);
    kp_net_subscribe(on_net_connect, NULL);

    if (!kp_task_spawn("koios_logship", ship_task, NULL,
            SHIP_TASK_STACK_BYTES, SHIP_TASK_PRIORITY)) {
        KP_LOGE(TAG, "Failed to start ship task; capture only");
        return;
    }
    s.running = true;
}

void koios_logship_flush(void) {
    wake_ship();
}

#else  // !CONFIG_KOIOS_SDK_LOGS_ENABLE

void koios_logship_init(const koios_logship_config_t* config) {
    (void)config;
    KP_LOGD("koios_logship", "disabled (CONFIG_KOIOS_SDK_LOGS_ENABLE not set)");
}

void koios_logship_flush(void) {}

#endif
