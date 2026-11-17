// Device metrics policy (portable).
//
// Samples the platform through kp_metrics, keeps the newest samples in a small
// ring while the cloudlink session is down, and sends them as
// {"type":"metrics","samples":[...]} text control frames. Mechanism (reading
// the numbers) lives behind the port; this file owns when to sample, what to
// keep, and the wire format.
//
// Compiled out unless CONFIG_KOIOS_SDK_METRICS_ENABLE is defined, like log
// shipping. The public functions always exist so callers link unconditionally.

#include "koios/metrics.h"

#include "koios/port/kp_log.h"

#if defined(CONFIG_KOIOS_SDK_METRICS_ENABLE)

#include "koios/cloudlink.h"
#include "koios/port/kp_metrics.h"
#include "koios/port/kp_os.h"

#include <cJSON.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char* TAG = "koios_metrics";

#ifdef CONFIG_KOIOS_SDK_METRICS_INTERVAL_S
#define DEFAULT_INTERVAL_S CONFIG_KOIOS_SDK_METRICS_INTERVAL_S
#else
#define DEFAULT_INTERVAL_S 60
#endif

#ifdef CONFIG_KOIOS_SDK_METRICS_BACKLOG
#define DEFAULT_BACKLOG CONFIG_KOIOS_SDK_METRICS_BACKLOG
#else
#define DEFAULT_BACKLOG 8
#endif

#define MIN_INTERVAL_S 10
#define MAX_INTERVAL_S 3600

#define MAX_GAUGES     8
#define GAUGE_NAME_LEN 16

// One frame stays well inside cloudlink's default 16 KiB message bound; a
// longer backlog goes out as several frames.
#define FRAME_CAP      8192
// Worst case of one serialised sample (every field, every gauge).
#define SAMPLE_JSON_MAX 1024

// Formatting floats is the deepest thing this task does.
#define TASK_STACK_BYTES 6144
#define TASK_PRIORITY    3
// While samples wait for the session, look for it this often.
#define READY_POLL_MS    5000

// Anything before this is "clock not set".
#define WALL_TIME_SANE_S 1600000000LL

typedef struct {
    char name[GAUGE_NAME_LEN];
    double value;
} gauge_t;

typedef struct {
    int64_t ts_ms;  // 0: the clock was not set
    kp_metrics_sample_t sys;
    gauge_t gauges[MAX_GAUGES];
    uint8_t gauge_count;
} sample_t;

static struct {
    bool running;
    kp_mutex_t lock;       // guards everything below
    kp_sem_t wake;

    uint32_t interval_s;   // 0: reporting stopped
    uint32_t default_interval_s;
    bool sample_now;

    sample_t* ring;
    size_t ring_cap, ring_head, ring_count;
    uint32_t dropped;      // samples overwritten before they could be sent
    uint32_t evictions;    // head moves caused by overwrites, ever

    gauge_t gauges[MAX_GAUGES];
    uint8_t gauge_count;

    bool reset_reported;   // reset_reason went out in a frame that was accepted
    char* frame;           // FRAME_CAP + 1
    char* one;             // SAMPLE_JSON_MAX: one rendered sample (metrics task only)
} s;

//------------------------------------------------------------------------------
// Serialisation
//------------------------------------------------------------------------------

typedef struct {
    char* buf;
    size_t cap, len;
    bool overflow;
} writer_t;

static void put(writer_t* w, const char* fmt, ...) {
    if (w->overflow) return;
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(w->buf + w->len, w->cap - w->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= w->cap - w->len) {
        w->overflow = true;
        return;
    }
    w->len += (size_t)n;
}

// Names and reasons come from the platform, not from a person, but they still
// go into JSON: keep what is harmless and replace the rest.
static void put_token(writer_t* w, const char* key, const char* value) {
    char safe[32];
    size_t n = 0;
    for (const char* p = value; *p && n + 1 < sizeof(safe); p++) {
        const char c = *p;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '.' || c == ':';
        safe[n++] = ok ? c : '_';
    }
    safe[n] = '\0';
    if (n) put(w, ",\"%s\":\"%s\"", key, safe);
}

// One sample as a JSON object. Returns its length, 0 when it does not fit.
static size_t render_sample(const sample_t* smp, bool with_reset, char* out, size_t out_cap) {
    writer_t w = { .buf = out, .cap = out_cap };
    const kp_metrics_sample_t* m = &smp->sys;
    const uint32_t f = m->fields;

    // The object always opens with a member so that every other one can lead
    // with a comma.
    put(&w, "{\"uptime_s\":%u", (f & KP_METRIC_UPTIME) ? (unsigned)m->uptime_s : 0u);
    if (smp->ts_ms > 0) put(&w, ",\"ts\":%lld", (long long)smp->ts_ms);
    if (f & KP_METRIC_CPU_PCT) put(&w, ",\"cpu_pct\":%.1f", (double)m->cpu_pct);
    if (f & KP_METRIC_CPU_CORES) put(&w, ",\"cpu_cores\":%u", (unsigned)m->cpu_cores);
    if (f & KP_METRIC_LOAD1) put(&w, ",\"load1\":%.2f", (double)m->load1);
    if (f & KP_METRIC_MEM) {
        put(&w, ",\"mem_total_bytes\":%llu,\"mem_free_bytes\":%llu",
            (unsigned long long)m->mem_total_bytes, (unsigned long long)m->mem_free_bytes);
    }
    if (f & KP_METRIC_MEM_MIN_FREE) {
        put(&w, ",\"mem_min_free_bytes\":%llu", (unsigned long long)m->mem_min_free_bytes);
    }
    if (f & KP_METRIC_MEM_LARGEST) {
        put(&w, ",\"mem_largest_block_bytes\":%llu", (unsigned long long)m->mem_largest_block_bytes);
    }
    if (f & KP_METRIC_MEM_INTERNAL) {
        put(&w, ",\"mem_internal_free_bytes\":%llu", (unsigned long long)m->mem_internal_free_bytes);
    }
    if (f & KP_METRIC_STORAGE) {
        put(&w, ",\"storage_total_bytes\":%llu,\"storage_free_bytes\":%llu",
            (unsigned long long)m->storage_total_bytes, (unsigned long long)m->storage_free_bytes);
    }
    if (f & KP_METRIC_TEMP) put(&w, ",\"temp_c\":%.1f", (double)m->temp_c);
    if (f & KP_METRIC_NET_COUNTERS) {
        put_token(&w, "net_iface", m->net_iface);
        put(&w, ",\"net_rx_bytes\":%llu,\"net_tx_bytes\":%llu",
            (unsigned long long)m->net_rx_bytes, (unsigned long long)m->net_tx_bytes);
    }
    if (f & KP_METRIC_NET_RSSI) put(&w, ",\"net_rssi_dbm\":%d", (int)m->net_rssi_dbm);
    if (f & KP_METRIC_TASKS) put(&w, ",\"tasks\":%u", (unsigned)m->tasks);
    if (with_reset && (f & KP_METRIC_RESET_REASON)) put_token(&w, "reset_reason", m->reset_reason);
    for (uint8_t i = 0; i < smp->gauge_count; i++) {
        put(&w, ",\"x_%s\":%.6g", smp->gauges[i].name, smp->gauges[i].value);
    }
    put(&w, "}");
    return w.overflow ? 0 : w.len;
}

//------------------------------------------------------------------------------
// Ring (lock held)
//------------------------------------------------------------------------------

static void ring_push(const sample_t* smp) {
    if (s.ring_count == s.ring_cap) {
        s.ring_head = (s.ring_head + 1) % s.ring_cap;  // the oldest goes
        s.ring_count--;
        s.dropped++;
        s.evictions++;
    }
    s.ring[(s.ring_head + s.ring_count) % s.ring_cap] = *smp;
    s.ring_count++;
}

//------------------------------------------------------------------------------
// Sample + ship
//------------------------------------------------------------------------------

static void take_sample(void) {
    sample_t smp;
    memset(&smp, 0, sizeof(smp));
    kp_metrics_sample(&smp.sys);
    const int64_t now_s = kp_wall_time_s();
    if (now_s > WALL_TIME_SANE_S) smp.ts_ms = now_s * 1000;

    if (!kp_mutex_take(s.lock, 1000)) return;
    smp.gauge_count = s.gauge_count;
    memcpy(smp.gauges, s.gauges, sizeof(gauge_t) * s.gauge_count);
    ring_push(&smp);
    kp_mutex_give(s.lock);
}

// Send what is waiting, oldest first. A frame that cloudlink does not take
// leaves its samples in the ring for the next round.
static void ship_pending(void) {
    static const char PREFIX[] = "{\"type\":\"metrics\",\"samples\":[";
    static const char SUFFIX[] = "]}";
    char* one = s.one;

    for (;;) {
        if (!koios_cloudlink_is_ready()) return;
        if (!kp_mutex_take(s.lock, 1000)) return;

        size_t len = sizeof(PREFIX) - 1;
        memcpy(s.frame, PREFIX, len);
        size_t packed = 0;
        bool sent_reset = false;
        for (size_t i = 0; i < s.ring_count; i++) {
            const sample_t* smp = &s.ring[(s.ring_head + i) % s.ring_cap];
            const bool with_reset = !s.reset_reported && !sent_reset;
            const size_t n = render_sample(smp, with_reset, one, SAMPLE_JSON_MAX);
            if (n == 0) {  // cannot happen with the sizes above; do not wedge on it
                packed++;
                continue;
            }
            if (len + n + (packed ? 1 : 0) + sizeof(SUFFIX) > FRAME_CAP) break;
            if (len > sizeof(PREFIX) - 1) s.frame[len++] = ',';
            memcpy(s.frame + len, one, n);
            len += n;
            packed++;
            if (with_reset && (smp->sys.fields & KP_METRIC_RESET_REASON)) sent_reset = true;
        }
        const bool have_body = len > sizeof(PREFIX) - 1;
        memcpy(s.frame + len, SUFFIX, sizeof(SUFFIX));  // with the NUL
        const uint32_t evictions_before = s.evictions;
        kp_mutex_give(s.lock);

        if (packed == 0) return;
        if (have_body && !koios_cloudlink_send_text(s.frame)) return;  // outbox full: later

        if (!kp_mutex_take(s.lock, 1000)) return;
        // Samples pushed meanwhile sit behind the ones just sent. An overflow
        // meanwhile already moved the head past some of the sent ones, and
        // what is at the head now was not in the frame.
        const uint32_t evicted = s.evictions - evictions_before;
        size_t drop = packed > evicted ? packed - evicted : 0;
        if (drop > s.ring_count) drop = s.ring_count;
        s.ring_head = (s.ring_head + drop) % s.ring_cap;
        s.ring_count -= drop;
        if (sent_reset) s.reset_reported = true;
        const size_t left = s.ring_count;
        const uint32_t dropped = s.dropped;
        s.dropped = 0;
        kp_mutex_give(s.lock);

        if (dropped) KP_LOGW(TAG, "%u sample(s) were overwritten while offline", (unsigned)dropped);
        if (left == 0) return;
    }
}

static void metrics_task(void* arg) {
    (void)arg;
    int64_t next_sample_us = kp_monotonic_us();  // the first sample goes out with the first session

    for (;;) {
        uint32_t interval_s = 0;
        bool now_requested = false;
        size_t waiting = 0;
        if (kp_mutex_take(s.lock, 1000)) {
            interval_s = s.interval_s;
            now_requested = s.sample_now;
            s.sample_now = false;
            waiting = s.ring_count;
            kp_mutex_give(s.lock);
        }

        const int64_t now = kp_monotonic_us();
        if (now_requested || (interval_s > 0 && now >= next_sample_us)) {
            take_sample();
            waiting++;
            if (interval_s > 0) next_sample_us = now + (int64_t)interval_s * 1000000;
        }
        if (waiting > 0) ship_pending();

        // Sleep until the next sample; sooner while a backlog waits for the session.
        uint32_t wait_ms = KP_WAIT_FOREVER;
        if (interval_s > 0) {
            const int64_t left_us = next_sample_us - kp_monotonic_us();
            wait_ms = left_us > 0 ? (uint32_t)((left_us + 999) / 1000) : 0;
        }
        bool backlog = false;
        if (kp_mutex_take(s.lock, 1000)) {
            backlog = s.ring_count > 0;
            kp_mutex_give(s.lock);
        }
        if (backlog && wait_ms > READY_POLL_MS) wait_ms = READY_POLL_MS;
        if (wait_ms > 0) kp_sem_take(s.wake, wait_ms);
    }
}

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

static uint32_t clamp_interval(uint32_t seconds) {
    if (seconds == 0) return 0;
    if (seconds < MIN_INTERVAL_S) return MIN_INTERVAL_S;
    if (seconds > MAX_INTERVAL_S) return MAX_INTERVAL_S;
    return seconds;
}

void koios_metrics_init(const koios_metrics_config_t* config) {
    if (s.running) return;

    s.interval_s = clamp_interval((config && config->interval_s) ? config->interval_s : DEFAULT_INTERVAL_S);
    s.default_interval_s = s.interval_s;
    s.ring_cap = (config && config->backlog) ? config->backlog : DEFAULT_BACKLOG;
    s.ring = kp_calloc(s.ring_cap, sizeof(sample_t));
    s.frame = kp_malloc(FRAME_CAP + 1);
    s.one = kp_malloc(SAMPLE_JSON_MAX);
    s.lock = kp_mutex_create();
    s.wake = kp_sem_create();
    if (!s.ring || !s.frame || !s.one || !s.lock || !s.wake) {
        KP_LOGE(TAG, "Failed to allocate; metrics off");
        return;
    }
    if (!kp_task_spawn("koios_metrics", metrics_task, NULL, TASK_STACK_BYTES, TASK_PRIORITY)) {
        KP_LOGE(TAG, "Failed to start the metrics task");
        return;
    }
    s.running = true;
    KP_LOGI(TAG, "Metrics every %u s (keeping %u while offline)",
        (unsigned)s.interval_s, (unsigned)s.ring_cap);
}

void koios_metrics_set_interval(uint32_t seconds) {
    if (!s.running) return;
    const uint32_t clamped = clamp_interval(seconds);
    bool changed = false;
    if (kp_mutex_take(s.lock, 1000)) {
        changed = s.interval_s != clamped;
        s.interval_s = clamped;
        // Sample right away under the new interval rather than waiting out the old one.
        if (changed && clamped > 0) s.sample_now = true;
        kp_mutex_give(s.lock);
    }
    if (changed) {
        if (clamped) KP_LOGI(TAG, "Interval is now %u s", (unsigned)clamped);
        else KP_LOGI(TAG, "Reporting stopped");
        kp_sem_give(s.wake);
    }
}

static bool valid_gauge_name(const char* name) {
    if (!name || !name[0]) return false;
    size_t n = 0;
    for (const char* p = name; *p; p++, n++) {
        const char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return n < GAUGE_NAME_LEN;
}

bool koios_metrics_gauge(const char* name, double value) {
    if (!s.running || !valid_gauge_name(name)) return false;
    // NaN and infinities have no JSON spelling.
    if (value != value || value > 1e300 || value < -1e300) return false;
    bool ok = false;
    if (kp_mutex_take(s.lock, 1000)) {
        uint8_t i = 0;
        while (i < s.gauge_count && strcmp(s.gauges[i].name, name) != 0) i++;
        if (i < MAX_GAUGES) {
            if (i == s.gauge_count) {
                snprintf(s.gauges[i].name, sizeof(s.gauges[i].name), "%s", name);
                s.gauge_count++;
            }
            s.gauges[i].value = value;
            ok = true;
        }
        kp_mutex_give(s.lock);
    }
    return ok;
}

void koios_metrics_gauge_clear(const char* name) {
    if (!s.running || !name) return;
    if (!kp_mutex_take(s.lock, 1000)) return;
    for (uint8_t i = 0; i < s.gauge_count; i++) {
        if (strcmp(s.gauges[i].name, name) != 0) continue;
        s.gauges[i] = s.gauges[s.gauge_count - 1];
        s.gauge_count--;
        break;
    }
    kp_mutex_give(s.lock);
}

void koios_metrics_report_now(void) {
    if (!s.running) return;
    if (kp_mutex_take(s.lock, 1000)) {
        s.sample_now = true;
        kp_mutex_give(s.lock);
    }
    kp_sem_give(s.wake);
}

void koios_metrics_on_twin_desired(const struct cJSON* desired) {
    if (!s.running || !desired) return;
    const cJSON* koios = cJSON_GetObjectItemCaseSensitive(desired, "koios");
    const cJSON* metrics = cJSON_GetObjectItemCaseSensitive(koios, "metrics");
    const cJSON* interval = cJSON_GetObjectItemCaseSensitive(metrics, "interval_s");
    // The desired document is the whole truth: a document without the key
    // means "the device's own default" again.
    if (!cJSON_IsNumber(interval)) {
        koios_metrics_set_interval(s.default_interval_s);
        return;
    }
    const double v = cJSON_GetNumberValue(interval);
    if (v < 0 || v > 1e9) return;
    koios_metrics_set_interval((uint32_t)v);
}

#else  // !CONFIG_KOIOS_SDK_METRICS_ENABLE

void koios_metrics_init(const koios_metrics_config_t* config) {
    (void)config;
    KP_LOGD("koios_metrics", "disabled (CONFIG_KOIOS_SDK_METRICS_ENABLE not set)");
}

void koios_metrics_set_interval(uint32_t seconds) { (void)seconds; }
bool koios_metrics_gauge(const char* name, double value) { (void)name; (void)value; return false; }
void koios_metrics_gauge_clear(const char* name) { (void)name; }
void koios_metrics_report_now(void) {}
void koios_metrics_on_twin_desired(const struct cJSON* desired) { (void)desired; }

#endif
