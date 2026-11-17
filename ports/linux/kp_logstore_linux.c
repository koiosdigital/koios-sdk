// Log store for Linux: the same byte ring as on an MCU (variable-length
// records packed into a fixed budget, the oldest evicted when it fills), kept
// in a file-backed mapping under state_dir so that lines captured before a
// crash or a restart of the process ship afterwards. Without a state_dir the
// ring lives in memory.
//
// Lines come from two places: the SDK's own log calls (kp_log_linux.c, when
// capture_own_logs is set) and koios_linux_log_push(), which the agent's
// journal follower and applications call.

#include "koios/port/kp_logstore.h"
#include "koios/port/kp_log.h"
#include "kp_linux.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define STORE_MAGIC   0x4B4C4F47u  // "KLOG"
#define STORE_VERSION 1u

typedef struct __attribute__((packed)) {
    int64_t  ts_ms;
    uint8_t  level;
    uint8_t  tag_len;
    uint16_t msg_len;
} rec_hdr_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t size;      // bytes of buf this header was written for
    uint32_t head;      // offset of the oldest record
    uint32_t tail;      // offset of the next write
    uint32_t used;      // bytes stored
    uint32_t dropped;   // records evicted before they shipped
    uint32_t reserved;
} store_hdr_t;

static struct {
    pthread_mutex_t lock;
    store_hdr_t* hdr;   // NULL until init
    uint8_t* buf;
    size_t size;
    void (*notify)(void);
    // Records removed from the head since start, by eviction or consume. A
    // peek remembers it so that a consume after an eviction does not drop
    // records the ship task never saw.
    uint64_t head_seq;
    uint64_t peek_seq;
} s = { .lock = PTHREAD_MUTEX_INITIALIZER };

static __thread bool tl_ship_task;

//------------------------------------------------------------------------------
// Ring primitives (lock held)
//------------------------------------------------------------------------------

static void ring_write(const void* src, size_t n) {
    const uint8_t* p = src;
    size_t first = s.size - s.hdr->tail;
    if (first > n) first = n;
    memcpy(s.buf + s.hdr->tail, p, first);
    if (n > first) memcpy(s.buf, p + first, n - first);
    s.hdr->tail = (uint32_t)((s.hdr->tail + n) % s.size);
}

static void ring_read(size_t off, void* dst, size_t n) {
    uint8_t* d = dst;
    size_t first = s.size - off;
    if (first > n) first = n;
    memcpy(d, s.buf + off, first);
    if (n > first) memcpy(d + first, s.buf, n - first);
}

static size_t record_size_at(size_t off) {
    rec_hdr_t h;
    ring_read(off, &h, sizeof(h));
    return sizeof(rec_hdr_t) + h.tag_len + h.msg_len;
}

static void drop_head(void) {
    size_t rs = record_size_at(s.hdr->head);
    if (rs > s.hdr->used) rs = s.hdr->used;  // corruption guard
    s.hdr->head = (uint32_t)((s.hdr->head + rs) % s.size);
    s.hdr->used -= (uint32_t)rs;
    s.head_seq++;
}

static void reset_locked(void) {
    s.hdr->magic = STORE_MAGIC;
    s.hdr->version = STORE_VERSION;
    s.hdr->size = (uint32_t)s.size;
    s.hdr->head = s.hdr->tail = s.hdr->used = s.hdr->dropped = 0;
}

// A mapping that came from disk is only trusted when every offset is in range
// and the records add up to exactly `used`.
static bool validate_locked(void) {
    const store_hdr_t* h = s.hdr;
    if (h->magic != STORE_MAGIC || h->version != STORE_VERSION || h->size != s.size) return false;
    if (h->head >= s.size || h->tail >= s.size || h->used > s.size) return false;
    if ((h->head + h->used) % s.size != h->tail) return false;
    size_t off = h->head, left = h->used;
    while (left > 0) {
        if (left < sizeof(rec_hdr_t)) return false;
        const size_t rs = record_size_at(off);
        if (rs > left) return false;
        off = (off + rs) % s.size;
        left -= rs;
    }
    return true;
}

//------------------------------------------------------------------------------
// Capture
//------------------------------------------------------------------------------

void kp_linux_logstore_push(int level, const char* tag, const char* msg, int64_t ts_ms) {
    if (tl_ship_task || !msg || !msg[0]) return;
    if (!tag) tag = "";

    size_t tl = strlen(tag), ml = strlen(msg);
    if (tl > KOIOS_LOG_TAG_LEN - 1) tl = KOIOS_LOG_TAG_LEN - 1;
    if (ml > KOIOS_LOG_MSG_LEN - 1) ml = KOIOS_LOG_MSG_LEN - 1;
    while (ml > 0 && (msg[ml - 1] == '\n' || msg[ml - 1] == '\r')) ml--;
    if (ml == 0) return;

    rec_hdr_t h = { .ts_ms = ts_ms, .level = (uint8_t)level,
                    .tag_len = (uint8_t)tl, .msg_len = (uint16_t)ml };
    const size_t rec = sizeof(h) + tl + ml;

    void (*notify)(void) = NULL;
    pthread_mutex_lock(&s.lock);
    if (s.hdr && rec <= s.size) {
        while (s.hdr->used + rec > s.size) {
            drop_head();
            s.hdr->dropped++;
        }
        ring_write(&h, sizeof(h));
        ring_write(tag, tl);
        ring_write(msg, ml);
        s.hdr->used += (uint32_t)rec;
        notify = s.notify;
    }
    pthread_mutex_unlock(&s.lock);
    if (notify) notify();
}

void koios_linux_log_push(int level, const char* tag, const char* msg, int64_t ts_ms) {
    kp_linux_logstore_push(level, tag, msg, ts_ms);
}

//------------------------------------------------------------------------------
// Port contract
//------------------------------------------------------------------------------

void kp_logstore_init(void) {
    pthread_mutex_lock(&s.lock);
    if (s.hdr) {
        pthread_mutex_unlock(&s.lock);
        return;
    }

    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    s.size = cfg->log_ring_bytes ? cfg->log_ring_bytes : (256u * 1024u);
    const size_t map_len = sizeof(store_hdr_t) + s.size;
    void* map = MAP_FAILED;
    bool from_disk = false;

    if (cfg->state_dir) {
        char path[560];
        snprintf(path, sizeof(path), "%s/logring", cfg->state_dir);
        const int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0640);
        if (fd >= 0) {
            struct stat st;
            from_disk = (fstat(fd, &st) == 0 && (size_t)st.st_size == map_len);
            if (ftruncate(fd, (off_t)map_len) == 0) {
                map = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            }
            close(fd);
        }
    }
    if (map == MAP_FAILED) {
        from_disk = false;
        map = calloc(1, map_len);
        if (!map) {
            pthread_mutex_unlock(&s.lock);
            return;
        }
    }

    s.hdr = map;
    s.buf = (uint8_t*)map + sizeof(store_hdr_t);
    if (!from_disk || !validate_locked()) reset_locked();
    const uint32_t survived = s.hdr->used;
    pthread_mutex_unlock(&s.lock);

    if (survived) {
        KP_LOGI("koios_logship", "recovered %u buffered log byte(s) from the last run",
            (unsigned)survived);
    }
}

size_t kp_logstore_used(void) {
    pthread_mutex_lock(&s.lock);
    const size_t n = s.hdr ? s.hdr->used : 0;
    pthread_mutex_unlock(&s.lock);
    return n;
}

size_t kp_logstore_capacity_bytes(void) {
    return s.size;
}

size_t kp_logstore_peek(koios_log_entry_t* out, size_t max) {
    if (!out || max == 0) return 0;
    size_t count = 0;
    pthread_mutex_lock(&s.lock);
    if (s.hdr) {
        size_t off = s.hdr->head, left = s.hdr->used;
        s.peek_seq = s.head_seq;
        while (count < max && left >= sizeof(rec_hdr_t)) {
            rec_hdr_t h;
            ring_read(off, &h, sizeof(h));
            const size_t rs = sizeof(rec_hdr_t) + h.tag_len + h.msg_len;
            if (rs > left) break;

            const size_t tcap = sizeof(out[count].tag) - 1;
            const size_t tcopy = h.tag_len < tcap ? h.tag_len : tcap;
            ring_read((off + sizeof(rec_hdr_t)) % s.size, out[count].tag, tcopy);
            out[count].tag[tcopy] = '\0';

            const size_t mcap = sizeof(out[count].msg) - 1;
            const size_t mcopy = h.msg_len < mcap ? h.msg_len : mcap;
            ring_read((off + sizeof(rec_hdr_t) + h.tag_len) % s.size, out[count].msg, mcopy);
            out[count].msg[mcopy] = '\0';

            out[count].ts_ms = h.ts_ms;
            out[count].level = h.level;

            off = (off + rs) % s.size;
            left -= rs;
            count++;
        }
    }
    pthread_mutex_unlock(&s.lock);
    return count;
}

void kp_logstore_consume(size_t n) {
    pthread_mutex_lock(&s.lock);
    if (s.hdr) {
        // Records evicted since the peek are already gone; they were counted
        // as dropped, and what sits at the head now was never shipped.
        const uint64_t evicted = s.head_seq - s.peek_seq;
        n = (evicted >= n) ? 0 : n - (size_t)evicted;
        while (n > 0 && s.hdr->used >= sizeof(rec_hdr_t)) {
            drop_head();
            n--;
        }
        s.peek_seq = s.head_seq;
    }
    pthread_mutex_unlock(&s.lock);
}

uint32_t kp_logstore_take_dropped(void) {
    pthread_mutex_lock(&s.lock);
    uint32_t d = 0;
    if (s.hdr) {
        d = s.hdr->dropped;
        s.hdr->dropped = 0;
    }
    pthread_mutex_unlock(&s.lock);
    return d;
}

void kp_logstore_set_notify(void (*cb)(void)) {
    pthread_mutex_lock(&s.lock);
    s.notify = cb;
    pthread_mutex_unlock(&s.lock);
}

void kp_logstore_mark_ship_task(void) {
    tl_ship_task = true;
}
