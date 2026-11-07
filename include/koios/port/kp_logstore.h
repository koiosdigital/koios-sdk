#pragma once

// Reset-surviving log store port. A port captures every leveled log line the
// platform emits and parks it in storage that survives a reset, brownout, or
// deep sleep (RTC-retained memory on ESP32) so lines written just before a
// crash still ship after the device comes back up. The portable ship policy
// (core/logship.c) drains this store and forwards batches to the Koios gateway.
//
// Capture runs from arbitrary task contexts, so the port must keep the push
// path short and lock-safe; the drain/consume calls run only from the ship
// task. Entries are fixed-size and self-contained (no pointers) so the ring
// can live in a noinit region.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Inline field sizes. Fixed so a record is self-contained in retained memory;
// overridable via Kconfig to trade RTC footprint against truncation.
#ifdef CONFIG_KOIOS_SDK_LOGS_TAG_LEN
#define KOIOS_LOG_TAG_LEN CONFIG_KOIOS_SDK_LOGS_TAG_LEN
#else
#define KOIOS_LOG_TAG_LEN 16
#endif

#ifdef CONFIG_KOIOS_SDK_LOGS_MSG_LEN
#define KOIOS_LOG_MSG_LEN CONFIG_KOIOS_SDK_LOGS_MSG_LEN
#else
#define KOIOS_LOG_MSG_LEN 160
#endif

typedef enum {
    KOIOS_LOG_NONE = 0,
    KOIOS_LOG_ERROR,
    KOIOS_LOG_WARN,
    KOIOS_LOG_INFO,
    KOIOS_LOG_DEBUG,
    KOIOS_LOG_VERBOSE,
} koios_log_level_t;

typedef struct {
    int64_t  ts_ms;   // wall-clock ms at capture, or 0 if the clock was unsynced
    uint32_t seq;     // capture sequence, for stable ordering / debugging
    uint8_t  level;   // koios_log_level_t
    char     tag[KOIOS_LOG_TAG_LEN];   // NUL-terminated, truncated
    char     msg[KOIOS_LOG_MSG_LEN];   // NUL-terminated, truncated
} koios_log_entry_t;

// Set up retained storage (validating/clearing it on a cold boot) and install
// the capture hook. Safe to call once; subsequent calls are ignored.
void kp_logstore_init(void);

// Number of entries currently buffered and ready to ship.
size_t kp_logstore_pending(void);

// Capacity of the store (max entries it can hold).
size_t kp_logstore_capacity(void);

// Copy up to max of the oldest entries into out (oldest first) without
// removing them. Returns the number copied.
size_t kp_logstore_peek(koios_log_entry_t* out, size_t max);

// Drop the n oldest entries. Call after a batch has been accepted upstream.
void kp_logstore_consume(size_t n);

// Return and clear the count of entries dropped because the store was full
// (oldest-overwritten). Lets the ship policy surface a gap marker.
uint32_t kp_logstore_take_dropped(void);

// Register a callback invoked (from the capture context) when a prompt flush
// is warranted — an error-level line, or the store crossing its high-water
// mark. The callback must be ISR-adjacent-safe and quick (e.g. post a sem).
void kp_logstore_set_notify(void (*cb)(void));

// Mark the calling task as the ship task: its own log output (and the HTTP /
// TLS chatter it drives) is not captured, preventing a shipping feedback loop.
void kp_logstore_mark_ship_task(void);

#ifdef __cplusplus
}
#endif
