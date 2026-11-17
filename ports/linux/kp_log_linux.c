// Leveled logging to stderr. Under systemd (JOURNAL_STREAM is set) each line
// starts with the "<N>" priority prefix journald understands; otherwise with
// the time and the level. Lines are optionally captured into the ship ring.

#include "koios/port/kp_log.h"
#include "koios/port/kp_logstore.h"
#include "kp_linux.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static int syslog_priority(kp_log_level_t level) {
    switch (level) {
    case KP_LOG_ERROR: return 3;
    case KP_LOG_WARN:  return 4;
    case KP_LOG_INFO:  return 6;
    default:           return 7;
    }
}

static const char* level_letter(kp_log_level_t level) {
    switch (level) {
    case KP_LOG_ERROR: return "E";
    case KP_LOG_WARN:  return "W";
    case KP_LOG_INFO:  return "I";
    default:           return "D";
    }
}

static int store_level(kp_log_level_t level) {
    switch (level) {
    case KP_LOG_ERROR: return KOIOS_LOG_ERROR;
    case KP_LOG_WARN:  return KOIOS_LOG_WARN;
    case KP_LOG_INFO:  return KOIOS_LOG_INFO;
    default:           return KOIOS_LOG_DEBUG;
    }
}

void kp_log_write(kp_log_level_t level, const char* tag, const char* fmt, ...) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    const bool to_stderr = (int)level <= cfg->log_level;
    // Debug lines are never shipped: they exist for a person at the terminal.
    const bool capture = cfg->capture_own_logs && level != KP_LOG_DEBUG;
    if (!to_stderr && !capture) return;

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (to_stderr) {
        static int under_journal = -1;
        if (under_journal < 0) under_journal = getenv("JOURNAL_STREAM") ? 1 : 0;
        if (under_journal) {
            fprintf(stderr, "<%d>%s: %s\n", syslog_priority(level), tag ? tag : "koios", msg);
        }
        else {
            struct tm tm;
            time_t secs = tv.tv_sec;
            localtime_r(&secs, &tm);
            fprintf(stderr, "%02d:%02d:%02d.%03d %s %s: %s\n",
                tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000),
                level_letter(level), tag ? tag : "koios", msg);
        }
    }

    if (capture) {
        const int64_t ts_ms = (tv.tv_sec > 1600000000)
            ? (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000 : 0;
        kp_linux_logstore_push(store_level(level), tag ? tag : "koios", msg, ts_ms);
    }
}
