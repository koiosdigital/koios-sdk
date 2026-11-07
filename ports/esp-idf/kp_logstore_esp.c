// RTC-retained log store + capture hook (ESP-IDF).
//
// Installs an esp_log_set_vprintf() hook that forwards every line to the
// previous sink (so the console still works) and parks a structured copy in a
// ring buffer held in RTC_NOINIT memory. RTC memory keeps its contents across
// resets, brownouts, and deep sleep, so the lines written just before a reboot
// survive it and ship once the device is back online. This is the lean
// RTC-store technique from esp-insights, not the whole agent.

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

#ifdef CONFIG_KOIOS_SDK_LOGS_RTC_RECORDS
#define RING_CAPACITY CONFIG_KOIOS_SDK_LOGS_RTC_RECORDS
#else
#define RING_CAPACITY 16
#endif

#define RTC_STORE_MAGIC 0x4B4C4F47u  // "KLOG"
// Flush early once the buffer is this full, before overwrite starts.
#define HIGH_WATER ((RING_CAPACITY * 3) / 4)
// Longest formatted line we parse; the stored message is capped separately.
#define KP_LOG_LINE_MAX 320

// Retained across resets/deep sleep. NOT cleared at startup — guarded by a
// magic so a cold boot (or a layout change) starts from a clean ring.
typedef struct {
    uint32_t magic;
    uint32_t head;      // index of oldest entry
    uint32_t count;     // entries currently stored
    uint32_t seq;       // ever-increasing capture counter
    uint32_t dropped;   // entries overwritten before they could ship
    koios_log_entry_t entries[RING_CAPACITY];
} rtc_store_t;

static RTC_NOINIT_ATTR rtc_store_t s_rtc;

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t s_prev_vprintf;
static void (*s_notify)(void);
static TaskHandle_t s_ship_task;
static bool s_installed;

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

static void parse_line(char* line, koios_log_entry_t* e) {
    strip_ansi(line);

    e->level = KOIOS_LOG_NONE;
    e->tag[0] = '\0';

    const char* msg = line;
    // "<L> (<ts>) <TAG>: <msg>"
    if (line[0] && line[1] == ' ' && line[2] == '(') {
        uint8_t lvl = level_from_letter(line[0]);
        char* paren = strstr(line, ") ");
        if (lvl != KOIOS_LOG_NONE && paren) {
            char* tag_start = paren + 2;
            char* colon = strstr(tag_start, ": ");
            if (colon) {
                e->level = lvl;
                size_t tag_len = (size_t)(colon - tag_start);
                if (tag_len >= sizeof(e->tag)) tag_len = sizeof(e->tag) - 1;
                memcpy(e->tag, tag_start, tag_len);
                e->tag[tag_len] = '\0';
                msg = colon + 2;
            }
        }
    }

    strlcpy(e->msg, msg, sizeof(e->msg));
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

    // Never capture the ship task's own output (and the HTTP/TLS chatter it
    // drives on the same task) — that would feed the buffer during a flush.
    if (s_ship_task && xTaskGetCurrentTaskHandle() == s_ship_task) return ret;

    koios_log_entry_t e = { 0 };
    parse_line(line, &e);
    if (e.msg[0] == '\0') return ret;  // nothing worth keeping

    struct timeval tv;
    gettimeofday(&tv, NULL);
    // Below ~2020 the clock hasn't synced; leave ts_ms 0 so the server stamps
    // receive time instead of a bogus (rejected-as-too-old) timestamp.
    e.ts_ms = (tv.tv_sec > 1600000000)
        ? (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000
        : 0;

    bool want_flush;
    portENTER_CRITICAL(&s_mux);
    e.seq = ++s_rtc.seq;
    uint32_t slot;
    if (s_rtc.count < RING_CAPACITY) {
        slot = (s_rtc.head + s_rtc.count) % RING_CAPACITY;
        s_rtc.count++;
    } else {
        slot = s_rtc.head;                       // overwrite oldest
        s_rtc.head = (s_rtc.head + 1) % RING_CAPACITY;
        s_rtc.dropped++;
    }
    s_rtc.entries[slot] = e;
    want_flush = (e.level == KOIOS_LOG_ERROR) || (s_rtc.count >= HIGH_WATER);
    portEXIT_CRITICAL(&s_mux);

    if (want_flush && s_notify) s_notify();
    return ret;
}

//------------------------------------------------------------------------------
// Port contract
//------------------------------------------------------------------------------

void kp_logstore_init(void) {
    if (s_installed) return;

    portENTER_CRITICAL(&s_mux);
    if (s_rtc.magic != RTC_STORE_MAGIC) {
        // Cold boot or incompatible layout: start clean.
        s_rtc.magic = RTC_STORE_MAGIC;
        s_rtc.head = s_rtc.count = s_rtc.seq = s_rtc.dropped = 0;
    }
    uint32_t survived = s_rtc.count;
    portEXIT_CRITICAL(&s_mux);

    s_prev_vprintf = esp_log_set_vprintf(log_vprintf);
    s_installed = true;

    if (survived) {
        KP_LOGI("koios_logship", "recovered %u buffered log line(s) from last boot",
            (unsigned)survived);
    }
}

size_t kp_logstore_capacity(void) {
    return RING_CAPACITY;
}

size_t kp_logstore_pending(void) {
    portENTER_CRITICAL(&s_mux);
    size_t n = s_rtc.count;
    portEXIT_CRITICAL(&s_mux);
    return n;
}

size_t kp_logstore_peek(koios_log_entry_t* out, size_t max) {
    if (!out || max == 0) return 0;
    portENTER_CRITICAL(&s_mux);
    size_t n = s_rtc.count < max ? s_rtc.count : max;
    for (size_t i = 0; i < n; i++) {
        out[i] = s_rtc.entries[(s_rtc.head + i) % RING_CAPACITY];
    }
    portEXIT_CRITICAL(&s_mux);
    return n;
}

void kp_logstore_consume(size_t n) {
    portENTER_CRITICAL(&s_mux);
    if (n > s_rtc.count) n = s_rtc.count;
    s_rtc.head = (s_rtc.head + n) % RING_CAPACITY;
    s_rtc.count -= n;
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
