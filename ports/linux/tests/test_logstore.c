// The log ring: order, eviction when full, what a consume drops after an
// eviction, and survival across processes (run "write" then "read").

#include "check.h"

#include "koios/linux.h"
#include "koios/port/kp_logstore.h"

#include <stdlib.h>

static int s_notified;
static void on_notify(void) { s_notified++; }

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s STATE_DIR write|read|memory\n", argv[0]);
        return 2;
    }
    const char* mode = argv[2];
    const bool in_memory = strcmp(mode, "memory") == 0;
    const koios_linux_config_t cfg = {
        .state_dir = in_memory ? NULL : argv[1],
        .log_ring_bytes = 4096,
    };
    CHECK_EQ(koios_linux_init(&cfg), 0);
    kp_logstore_init();
    CHECK_EQ(kp_logstore_capacity_bytes(), 4096);

    koios_log_entry_t out[64];

    if (strcmp(mode, "read") == 0) {
        // What the "write" process left behind.
        const size_t n = kp_logstore_peek(out, 64);
        CHECK_EQ(n, 2);
        CHECK_STR(out[0].tag, "boot");
        CHECK_STR(out[0].msg, "survives the process");
        CHECK_EQ(out[0].level, KOIOS_LOG_WARN);
        CHECK_EQ(out[0].ts_ms, 1700000000123LL);
        CHECK_STR(out[1].msg, "second line");
        kp_logstore_consume(n);
        CHECK_EQ(kp_logstore_used(), 0);
        CHECK_DONE();
    }

    kp_logstore_set_notify(on_notify);
    CHECK_EQ(kp_logstore_used(), 0);

    // Order and fields.
    koios_linux_log_push(KOIOS_LOG_INFO, "a", "one", 1);
    koios_linux_log_push(KOIOS_LOG_ERROR, "b", "two\n", 2);  // the newline goes
    koios_linux_log_push(KOIOS_LOG_INFO, "c", "", 3);        // empty: not stored
    CHECK_EQ(s_notified, 2);
    size_t n = kp_logstore_peek(out, 64);
    CHECK_EQ(n, 2);
    CHECK_STR(out[0].msg, "one");
    CHECK_STR(out[1].msg, "two");
    CHECK_EQ(out[1].level, KOIOS_LOG_ERROR);
    CHECK_EQ(kp_logstore_peek(out, 1), 1);  // peek does not remove
    kp_logstore_consume(1);
    n = kp_logstore_peek(out, 64);
    CHECK_EQ(n, 1);
    CHECK_STR(out[0].msg, "two");
    kp_logstore_consume(5);  // more than there is
    CHECK_EQ(kp_logstore_used(), 0);

    // Long fields are cut to the caps, never overrun.
    char longmsg[4000];
    memset(longmsg, 'x', sizeof(longmsg) - 1);
    longmsg[sizeof(longmsg) - 1] = '\0';
    koios_linux_log_push(KOIOS_LOG_INFO, "a-tag-that-is-much-longer-than-the-store-keeps-for-one-line-of-log", longmsg, 0);
    n = kp_logstore_peek(out, 64);
    CHECK_EQ(n, 1);
    CHECK_EQ(strlen(out[0].msg), KOIOS_LOG_MSG_LEN - 1);
    CHECK_EQ(strlen(out[0].tag), KOIOS_LOG_TAG_LEN - 1);
    kp_logstore_consume(1);

    // Fill past the ring: the oldest go, the newest stay, the count is kept.
    char msg[64];
    for (int i = 0; i < 400; i++) {
        snprintf(msg, sizeof(msg), "line %04d padded out to a fixed width", i);
        koios_linux_log_push(KOIOS_LOG_INFO, "fill", msg, i);
    }
    CHECK(kp_logstore_used() <= 4096);
    n = kp_logstore_peek(out, 64);
    CHECK_EQ(n, 64);
    const uint32_t dropped = kp_logstore_take_dropped();
    CHECK(dropped > 300 && dropped < 400);
    CHECK_EQ(kp_logstore_take_dropped(), 0);
    int first = -1;
    sscanf(out[0].msg, "line %d", &first);
    CHECK_EQ(first, (int)dropped);  // exactly the dropped ones are missing

    // An eviction between peek and consume: the consume must not drop
    // records the peek never returned.
    n = kp_logstore_peek(out, 4);
    CHECK_EQ(n, 4);
    for (int i = 400; i < 403; i++) {  // three pushes evict three old records
        snprintf(msg, sizeof(msg), "line %04d padded out to a fixed width", i);
        koios_linux_log_push(KOIOS_LOG_INFO, "fill", msg, i);
    }
    const uint32_t evicted = kp_logstore_take_dropped();
    CHECK(evicted >= 3);
    kp_logstore_consume(4);
    n = kp_logstore_peek(out, 1);
    CHECK_EQ(n, 1);
    int head = -1;
    sscanf(out[0].msg, "line %d", &head);
    // The head moved by max(4, evicted), not by 4 + evicted.
    CHECK_EQ(head, first + (int)(evicted > 4 ? evicted : 4));

    // Leave two records for the "read" process.
    while (kp_logstore_peek(out, 64) > 0) kp_logstore_consume(64);
    kp_logstore_take_dropped();
    koios_linux_log_push(KOIOS_LOG_WARN, "boot", "survives the process", 1700000000123LL);
    koios_linux_log_push(KOIOS_LOG_INFO, "boot", "second line", 0);
    CHECK_DONE();
}
