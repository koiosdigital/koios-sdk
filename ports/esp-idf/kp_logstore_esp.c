// RTC-retained byte-ring log store + capture hook (ESP-IDF).
//
// Installs an esp_log_set_vprintf() hook that forwards every line to the
// previous sink (so the console still works) and packs a structured copy into a
// fixed byte ring held in RTC_NOINIT memory. RTC memory keeps its contents
// across resets, brownouts, and deep sleep, so the lines written just before a
// reboot survive it and ship once the device is back online. The ring is sized
// in BYTES, not lines: variable-length records are packed in and the oldest are
// evicted when it fills. This is the lean RTC-store technique from esp-insights,
// not the whole agent.

#include "koios/port/kp_logstore.h"
#include "koios/port/kp_log.h"

#include "sdkconfig.h"

#if CONFIG_KOIOS_SDK_LOGS_ENABLE

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_attr.h>
#include <esp_log.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#ifdef CONFIG_KOIOS_SDK_LOGS_RTC_BYTES
#define RING_BYTES CONFIG_KOIOS_SDK_LOGS_RTC_BYTES
#else
#define RING_BYTES 2048
#endif

#define RTC_STORE_MAGIC 0x4B4C4F47u  // "KLOG"
// Longest formatted line we parse; the stored message is capped separately.
#define KP_LOG_LINE_MAX 320

// One stored record: a packed header, then tag_len tag bytes, then msg_len msg
// bytes. memcpy'd in/out of the ring, so its alignment in the buffer is moot.
typedef struct __attribute__((packed)) {
    int64_t  ts_ms;
    uint8_t  level;
    uint8_t  tag_len;
    uint16_t msg_len;
} rec_hdr_t;

// Retained across resets/deep sleep. NOT cleared at startup — guarded by a
// magic + size so a cold boot (or a ring-size change) starts from a clean ring.
typedef struct {
    uint32_t magic;
    uint32_t size;      // RING_BYTES this buffer was framed for
    uint32_t head;      // byte offset of the oldest record
    uint32_t tail;      // byte offset of the next write
    uint32_t used;      // bytes currently stored
    uint32_t dropped;   // records evicted before they could ship
    uint8_t  buf[RING_BYTES];
} rtc_store_t;

static RTC_NOINIT_ATTR rtc_store_t s_rtc;

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t s_prev_vprintf;
static void (*s_notify)(void);
static TaskHandle_t s_ship_task;
static bool s_installed;

//------------------------------------------------------------------------------
// Byte-ring primitives (call under s_mux)
//------------------------------------------------------------------------------

static void ring_write(const void* src, size_t n) {
    const uint8_t* p = (const uint8_t*)src;
    size_t first = RING_BYTES - s_rtc.tail;
    if (first > n) first = n;
    memcpy(&s_rtc.buf[s_rtc.tail], p, first);
    if (n > first) memcpy(&s_rtc.buf[0], p + first, n - first);
    s_rtc.tail = (uint32_t)((s_rtc.tail + n) % RING_BYTES);
}

static void ring_read(size_t off, void* dst, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    size_t first = RING_BYTES - off;
    if (first > n) first = n;
    memcpy(d, &s_rtc.buf[off], first);
    if (n > first) memcpy(d + first, &s_rtc.buf[0], n - first);
}

static size_t record_size_at(size_t off) {
    rec_hdr_t h;
    ring_read(off, &h, sizeof(h));
    return sizeof(rec_hdr_t) + h.tag_len + h.msg_len;
}

static void evict_oldest(void) {
    size_t rs = record_size_at(s_rtc.head);
    if (rs > s_rtc.used) rs = s_rtc.used;  // corruption guard
    s_rtc.head = (uint32_t)((s_rtc.head + rs) % RING_BYTES);
    s_rtc.used -= rs;
    s_rtc.dropped++;
}

static void push_record(int64_t ts_ms, uint8_t level, const char* tag, const char* msg) {
    rec_hdr_t h;
    size_t tl = strlen(tag);
    size_t ml = strlen(msg);
    if (tl > 255) tl = 255;
    if (ml > 0xFFFF) ml = 0xFFFF;
    h.ts_ms = ts_ms;
    h.level = level;
    h.tag_len = (uint8_t)tl;
    h.msg_len = (uint16_t)ml;
    size_t rec = sizeof(rec_hdr_t) + tl + ml;
    if (rec > RING_BYTES) return;  // a single record can never exceed the ring

    portENTER_CRITICAL(&s_mux);
    while (s_rtc.used + rec > RING_BYTES) evict_oldest();
    ring_write(&h, sizeof(h));
    ring_write(tag, tl);
    ring_write(msg, ml);
    s_rtc.used += (uint32_t)rec;
    portEXIT_CRITICAL(&s_mux);
}

//------------------------------------------------------------------------------
// Line parsing: "<L> (<ts>) <TAG>: <message>" with optional ANSI color, the
// standard ESP-IDF log layout. Anything that doesn't match is stored whole.
//------------------------------------------------------------------------------

static uint8_t level_from_letter(char c) {
    switch (c) {
    case 'E': return KOIOS_LOG_ERROR;
    case 'W': return KOIOS_LOG_WARN;
    case 'I': return KOIOS_LOG_INFO;
    case 'D': return KOIOS_LOG_DEBUG;
    case 'V': return KOIOS_LOG_VERBOSE;
    default:  return KOIOS_LOG_NONE;
    }
}

// Strip ANSI CSI escapes (\e[ ... m) and trailing CR/LF in place.
static void strip_ansi(char* s) {
    char* w = s;
    for (char* r = s; *r; r++) {
        if (*r == 0x1b) {
            while (*r && *r != 'm') r++;
            if (*r == 'm') continue;  // the 'm' itself is skipped by the loop step
            break;                    // unterminated escape; stop
        }
        *w++ = *r;
    }
    *w = '\0';
    while (w > s && (w[-1] == '\n' || w[-1] == '\r')) *--w = '\0';
}

// Parse a formatted line into level + NUL-terminated tag/msg (both truncated).
static uint8_t parse_line(char* line, char* tag, size_t tag_cap, char* msg, size_t msg_cap) {
    strip_ansi(line);

    uint8_t level = KOIOS_LOG_NONE;
    tag[0] = '\0';
    const char* src = line;

    // "<L> (<ts>) <TAG>: <msg>"
    if (line[0] && line[1] == ' ' && line[2] == '(') {
        uint8_t lvl = level_from_letter(line[0]);
        char* paren = strstr(line, ") ");
        if (lvl != KOIOS_LOG_NONE && paren) {
            char* tag_start = paren + 2;
            char* colon = strstr(tag_start, ": ");
            if (colon) {
                level = lvl;
                size_t tl = (size_t)(colon - tag_start);
                if (tl >= tag_cap) tl = tag_cap - 1;
                memcpy(tag, tag_start, tl);
                tag[tl] = '\0';
                src = colon + 2;
            }
        }
    }

    strlcpy(msg, src, msg_cap);
    return level;
}

//------------------------------------------------------------------------------
// Capture hook
//------------------------------------------------------------------------------

static int log_vprintf(const char* fmt, va_list ap) {
    // Format our own copy first, then forward the untouched list to the
    // previous sink so console output is unaffected.
    char line[KP_LOG_LINE_MAX];
    va_list cp;
    va_copy(cp, ap);
    vsnprintf(line, sizeof(line), fmt, cp);
    va_end(cp);

    int ret = s_prev_vprintf ? s_prev_vprintf(fmt, ap) : vprintf(fmt, ap);

    // Never capture the ship task's own output — that would feed the buffer.
    if (s_ship_task && xTaskGetCurrentTaskHandle() == s_ship_task) return ret;

    char tag[KOIOS_LOG_TAG_LEN];
    char msg[KOIOS_LOG_MSG_LEN];
    uint8_t level = parse_line(line, tag, sizeof(tag), msg, sizeof(msg));
    if (msg[0] == '\0') return ret;  // nothing worth keeping

    struct timeval tv;
    gettimeofday(&tv, NULL);
    // Below ~2020 the clock hasn't synced; leave ts_ms 0 so the server stamps
    // receive time instead of a bogus (rejected-as-too-old) timestamp.
    int64_t ts_ms = (tv.tv_sec > 1600000000)
        ? (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000
        : 0;

    push_record(ts_ms, level, tag, msg);

    // Ship as it arrives: nudge the ship task on every line (it forwards only
    // while the session is ready, so an offline nudge is a cheap no-op).
    if (s_notify) s_notify();
    return ret;
}

//------------------------------------------------------------------------------
// Port contract
//------------------------------------------------------------------------------

void kp_logstore_init(void) {
    if (s_installed) return;

    portENTER_CRITICAL(&s_mux);
    if (s_rtc.magic != RTC_STORE_MAGIC || s_rtc.size != RING_BYTES) {
        // Cold boot or a ring-size change: start clean.
        s_rtc.magic = RTC_STORE_MAGIC;
        s_rtc.size = RING_BYTES;
        s_rtc.head = s_rtc.tail = s_rtc.used = s_rtc.dropped = 0;
    }
    uint32_t survived = s_rtc.used;
    portEXIT_CRITICAL(&s_mux);

    s_prev_vprintf = esp_log_set_vprintf(log_vprintf);
    s_installed = true;

    if (survived) {
        KP_LOGI("koios_logship", "recovered %u buffered log byte(s) from last boot",
            (unsigned)survived);
    }
}

size_t kp_logstore_used(void) {
    portENTER_CRITICAL(&s_mux);
    size_t n = s_rtc.used;
    portEXIT_CRITICAL(&s_mux);
    return n;
}

size_t kp_logstore_capacity_bytes(void) {
    return RING_BYTES;
}

size_t kp_logstore_peek(koios_log_entry_t* out, size_t max) {
    if (!out || max == 0) return 0;
    portENTER_CRITICAL(&s_mux);
    size_t off = s_rtc.head;
    size_t remaining = s_rtc.used;
    size_t count = 0;
    while (count < max && remaining >= sizeof(rec_hdr_t)) {
        rec_hdr_t h;
        ring_read(off, &h, sizeof(h));
        size_t rs = sizeof(rec_hdr_t) + h.tag_len + h.msg_len;
        if (rs > remaining) break;  // partial/corrupt guard

        size_t tcap = sizeof(out[count].tag) - 1;
        size_t tcopy = h.tag_len < tcap ? h.tag_len : tcap;
        ring_read((off + sizeof(rec_hdr_t)) % RING_BYTES, out[count].tag, tcopy);
        out[count].tag[tcopy] = '\0';

        size_t mcap = sizeof(out[count].msg) - 1;
        size_t mcopy = h.msg_len < mcap ? h.msg_len : mcap;
        ring_read((off + sizeof(rec_hdr_t) + h.tag_len) % RING_BYTES, out[count].msg, mcopy);
        out[count].msg[mcopy] = '\0';

        out[count].ts_ms = h.ts_ms;
        out[count].level = h.level;

        off = (off + rs) % RING_BYTES;
        remaining -= rs;
        count++;
    }
    portEXIT_CRITICAL(&s_mux);
    return count;
}

void kp_logstore_consume(size_t n) {
    portENTER_CRITICAL(&s_mux);
    while (n > 0 && s_rtc.used >= sizeof(rec_hdr_t)) {
        size_t rs = record_size_at(s_rtc.head);
        if (rs > s_rtc.used) break;
        s_rtc.head = (uint32_t)((s_rtc.head + rs) % RING_BYTES);
        s_rtc.used -= (uint32_t)rs;
        n--;
    }
    portEXIT_CRITICAL(&s_mux);
}

uint32_t kp_logstore_take_dropped(void) {
    portENTER_CRITICAL(&s_mux);
    uint32_t d = s_rtc.dropped;
    s_rtc.dropped = 0;
    portEXIT_CRITICAL(&s_mux);
    return d;
}

void kp_logstore_set_notify(void (*cb)(void)) {
    s_notify = cb;
}

void kp_logstore_mark_ship_task(void) {
    s_ship_task = xTaskGetCurrentTaskHandle();
}

#endif  // CONFIG_KOIOS_SDK_LOGS_ENABLE
