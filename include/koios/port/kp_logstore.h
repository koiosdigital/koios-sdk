#pragma once

// Reset-surviving log store port. A port captures every leveled log line the
// platform emits and parks it in storage that survives a reset, brownout, or
// deep sleep (RTC-retained memory on ESP32) so lines written just before a
// crash still ship after the device comes back up. The portable ship policy
// (core/logship.c) drains this store and forwards batches to the Koios gateway.
//
// The store is a **byte-sized ring** (not a fixed line count): variable-length
// records are packed into a fixed byte budget, and the oldest are evicted when
// it fills. Capture runs from arbitrary task contexts, so the port keeps the
// push path short and lock-safe; the peek/consume calls run only from the ship
// task. Records are self-contained (no pointers) so the ring lives in a noinit
// region, and each line is truncated to the tag/message caps below.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Per-line field caps. A line longer than these is truncated before storage,
// which bounds a single record and the decode buffers; overridable via Kconfig.
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

// A decoded record handed to the ship policy. The ring stores records packed by
// their actual byte length; peek decodes them into this fixed shape.
typedef struct {
    int64_t ts_ms;   // wall-clock ms at capture, or 0 if the clock was unsynced
    uint8_t level;   // koios_log_level_t
    char    tag[KOIOS_LOG_TAG_LEN];   // NUL-terminated, truncated
    char    msg[KOIOS_LOG_MSG_LEN];   // NUL-terminated, truncated
} koios_log_entry_t;

// Set up the retained byte ring (validating/clearing it on a cold boot or a
// size/layout change) and install the capture hook. Safe to call once.
void kp_logstore_init(void);

// Bytes of records currently buffered (0 when empty).
size_t kp_logstore_used(void);

// Total size of the ring in bytes.
size_t kp_logstore_capacity_bytes(void);

// Decode up to max of the oldest records into out (oldest first) without
// removing them. Returns the number decoded.
size_t kp_logstore_peek(koios_log_entry_t* out, size_t max);

// Drop the n oldest records. Call after a batch has been shipped.
void kp_logstore_consume(size_t n);

// Return and clear the count of records dropped because the ring was full
// (oldest-overwritten). Lets the ship policy surface a gap marker.
uint32_t kp_logstore_take_dropped(void);

// Register a callback invoked (from the capture context) after every stored
// line, so the ship task can forward it as it arrives. Must be ISR-adjacent-
// safe and quick (e.g. post a sem).
void kp_logstore_set_notify(void (*cb)(void));

// Mark the calling task as the ship task: its own log output is not captured,
// preventing a shipping feedback loop.
void kp_logstore_mark_ship_task(void);

#ifdef __cplusplus
}
#endif
