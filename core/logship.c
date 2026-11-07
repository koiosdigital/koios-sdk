// Log shipping policy (portable).
//
// Drains the reset-surviving log store (kp_logstore) and streams batches to the
// Koios gateway as a `{"type":"logs","logs":[...]}` text control frame over the
// existing cloudlink websocket. The frame rides the already-authenticated
// device session, so there is no separate HTTP host, no bearer token, and no
// `logs.write` capability to provision — the gateway stamps the connection's
// device/fleet/tenant identity onto every line.
//
// Mechanism (capture, retained storage, RTOS, the socket itself) lives behind
// the kp_* ports and cloudlink; this file owns only policy: when to flush, how
// to batch, how to serialize, and how to react to a full outbox.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char* TAG = "koios_logship";

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

// Building JSON + enqueuing a frame is light (no TLS on this task — cloudlink's
// sender does the socket write), so a small stack is enough.
#define SHIP_TASK_STACK_BYTES 4096
#define SHIP_TASK_PRIORITY    4
// While logs are waiting but the session is not up yet, re-check readiness on
// this short cadence instead of the full flush interval, so the reset-survived
// tail ships promptly once the link comes up.
#define READY_POLL_MS         3000
// Records decoded from the byte ring per peek; a larger backlog drains across
// several peeks. Bounds the scratch array, independent of the ring's byte size.
#define PEEK_BATCH            16

static const char* FRAME_PREFIX = "{\"type\":\"logs\",\"logs\":[";
static const char* FRAME_SUFFIX = "]}";

static struct {
    uint32_t flush_interval_ms;
    kp_sem_t wake;
    koios_log_entry_t* batch;   // peek scratch, capacity entries
    size_t batch_cap;
    char* body;                 // frame assembly buffer, BODY_CAP + 1 bytes
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

// Render one record as a JSON object (no trailing comma) into out. Returns the
// length, or 0 if it would not fit.
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
// Frame assembly + ship
//------------------------------------------------------------------------------

// Build {"type":"logs","logs":[...]} into s.body for as many of the n entries
// as fit, plus an optional leading overflow-gap marker. Returns the number of
// entries packed; *has_records is set when the array holds at least one object.
static size_t build_frame(const koios_log_entry_t* batch, size_t n,
    uint32_t dropped, bool* has_records) {
    char rec[KOIOS_LOG_TAG_LEN * 2 + KOIOS_LOG_MSG_LEN * 6 + 64];
    const size_t reserve = strlen(FRAME_SUFFIX) + 1;  // "]}" + NUL

    size_t len = strlen(FRAME_PREFIX);
    memcpy(s.body, FRAME_PREFIX, len);
    bool any = false;

    // Lead with a gap marker when lines were overwritten before shipping.
    if (dropped) {
        char note[96];
        snprintf(note, sizeof(note),
            "dropped %u buffered log line(s) (device buffer overflow)",
            (unsigned)dropped);
        size_t rl = render_record(rec, sizeof(rec), KOIOS_LOG_WARN, TAG, note, 0);
        if (rl && len + rl + reserve <= BODY_CAP) {
            memcpy(s.body + len, rec, rl);
            len += rl;
            any = true;
        }
    }

    size_t packed = 0;
    for (size_t i = 0; i < n; i++) {
        size_t rl = render_record(rec, sizeof(rec), batch[i].level,
            batch[i].tag, batch[i].msg, batch[i].ts_ms);
        if (rl == 0) { packed++; continue; }  // unrenderable; skip but consume
        size_t need = rl + (any ? 1 : 0);     // +1 for a separating comma
        if (len + need + reserve > BODY_CAP) break;  // frame full
        if (any) s.body[len++] = ',';
        memcpy(s.body + len, rec, rl);
        len += rl;
        any = true;
        packed++;
    }

    memcpy(s.body + len, FRAME_SUFFIX, strlen(FRAME_SUFFIX));
    len += strlen(FRAME_SUFFIX);
    s.body[len] = '\0';
    *has_records = any;
    return packed;
}

// Drain the store to the gateway over the websocket. Keeps entries buffered on
// any send failure (outbox full / link down) so the next flush retries them.
static void ship_pending(void) {
    uint32_t dropped = kp_logstore_take_dropped();
    bool first = true;

    for (;;) {
        size_t n = kp_logstore_peek(s.batch, s.batch_cap);
        if (n == 0 && !(first && dropped)) break;

        bool has_records = false;
        size_t packed = build_frame(s.batch, n, first ? dropped : 0, &has_records);

        if (!has_records) {
            // Only unrenderable entries fit; drop them rather than wedge the
            // buffer, then stop.
            if (packed > 0) kp_logstore_consume(packed);
            break;
        }

        // Re-check right before sending; if the link dropped, retry next flush.
        if (!koios_cloudlink_is_ready()) return;
        if (!koios_cloudlink_send_text(s.body)) return;  // outbox full; keep + retry

        kp_logstore_consume(packed);
        first = false;
        dropped = 0;
        if (packed < n) continue;       // frame-capped batch; more remain
        if (n < s.batch_cap) break;     // peeked the whole store
        // n == batch_cap: there may be more; loop again.
    }
}

static void ship_task(void* arg) {
    (void)arg;
    kp_logstore_mark_ship_task();
    KP_LOGI(TAG, "Log shipping active (over cloudlink, ship-on-arrival, %u-byte buffer)",
        (unsigned)kp_logstore_capacity_bytes());

    for (;;) {
        // Capture nudges this task per line, so a ready link ships as lines
        // arrive. Poll readiness quickly while a backlog waits for the link;
        // otherwise sleep the full interval as a retry/fallback.
        bool waiting = kp_logstore_used() > 0 && !koios_cloudlink_is_ready();
        kp_sem_take(s.wake, waiting ? READY_POLL_MS : s.flush_interval_ms);

        if (!koios_cloudlink_is_ready()) continue;
        if (kp_logstore_used() == 0) continue;
        ship_pending();
    }
}

static void wake_ship(void) {
    if (s.wake) kp_sem_give(s.wake);
}

static void on_net_connect(void) {
    // Nudge the ship task when the interface comes up; it still waits for the
    // cloudlink session to be ready before sending.
    wake_ship();
}

void koios_logship_init(const koios_logship_config_t* config) {
    if (s.running) return;
    s.flush_interval_ms = (config && config->flush_interval_ms)
        ? config->flush_interval_ms
        : DEFAULT_FLUSH_INTERVAL_MS;

    // Capture first so boot lines are recorded even if the rest fails.
    kp_logstore_init();

    s.batch_cap = PEEK_BATCH;
    s.batch = kp_malloc(s.batch_cap * sizeof(koios_log_entry_t));
    s.body = kp_malloc(BODY_CAP + 1);  // +1 for the NUL after a full frame
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
