// OS primitives over POSIX threads, and the port's stored configuration.
//
// Mutexes and semaphores are a flag under a pthread mutex with a condition
// variable, because the core needs timed takes and macOS (which the tests and
// the operator tools build on) has no pthread_mutex_timedlock. Timers share
// one thread; their callbacks must be short, as on every port.

#include "koios/port/kp_os.h"
#include "kp_linux.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/random.h>
#else
#include <sys/random.h>
#endif

//------------------------------------------------------------------------------
// Configuration
//------------------------------------------------------------------------------

static kp_linux_cfg_t s_cfg;
static pthread_mutex_t s_persist_lock = PTHREAD_MUTEX_INITIALIZER;

static char* dup_or_null(const char* s) {
    return (s && s[0]) ? strdup(s) : NULL;
}

const kp_linux_cfg_t* kp_linux_cfg(void) {
    return &s_cfg;
}

int kp_linux_mkdirs(const char* path, int mode) {
    if (!path || !path[0]) return -1;
    char buf[512];
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf)) return -1;
    for (char* p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, (mode_t)mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, (mode_t)mode) != 0 && errno != EEXIST) return -1;
    struct stat st;
    return (stat(buf, &st) == 0 && S_ISDIR(st.st_mode)) ? 0 : -1;
}

char* kp_linux_read_file(const char* path, size_t* len) {
    if (len) *len = 0;
    if (!path) return NULL;
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char* buf = malloc(cap);
    while (buf) {
        size_t got = fread(buf + n, 1, cap - n - 1, f);
        n += got;
        if (got == 0) break;
        if (n + 1 >= cap) {
            if (cap >= (16u << 20)) break;  // 16 MiB is far beyond any file read here
            char* grown = realloc(buf, cap * 2);
            if (!grown) { free(buf); buf = NULL; break; }
            buf = grown;
            cap *= 2;
        }
    }
    fclose(f);
    if (!buf) return NULL;
    buf[n] = '\0';
    if (len) *len = n;
    return buf;
}

int koios_linux_init(const koios_linux_config_t* cfg) {
    static const koios_linux_config_t none;
    if (!cfg) cfg = &none;

    s_cfg.cert_file = dup_or_null(cfg->cert_file);
    s_cfg.extra_chain_file = dup_or_null(cfg->extra_chain_file);
    s_cfg.key = dup_or_null(cfg->key);
    s_cfg.identity_ready_file = dup_or_null(cfg->identity_ready_file);
    s_cfg.ca_file = dup_or_null(cfg->ca_file);
    s_cfg.project = dup_or_null(cfg->project);
    s_cfg.version = dup_or_null(cfg->version);
    s_cfg.state_dir = dup_or_null(cfg->state_dir);
    s_cfg.runtime_dir = dup_or_null(cfg->runtime_dir);
    s_cfg.log_ring_bytes = cfg->log_ring_bytes ? cfg->log_ring_bytes : (256u * 1024u);
    s_cfg.log_level = (cfg->log_level >= 0 && cfg->log_level <= 3) ? cfg->log_level : 2;
    s_cfg.capture_own_logs = cfg->capture_own_logs;
    s_cfg.storage_path = strdup((cfg->storage_path && cfg->storage_path[0]) ? cfg->storage_path : "/");
    s_cfg.net_iface = dup_or_null(cfg->net_iface);
    s_cfg.ota_staging_dir = dup_or_null(cfg->ota_staging_dir);
    s_cfg.ota_apply_cmd = dup_or_null(cfg->ota_apply_cmd);
    s_cfg.ota_restart_cmd = dup_or_null(cfg->ota_restart_cmd);
    s_cfg.restart_handler = cfg->restart_handler;

    if (cfg->device_class && cfg->device_class[0]) {
        s_cfg.device_class = strdup(cfg->device_class);
    }
    else {
        // "linux-<machine>": aarch64 is reported as arm64, the name the
        // platform's class list uses.
        struct utsname u;
        char cls[80] = "linux";
        if (uname(&u) == 0) {
            const char* m = u.machine;
            if (strcmp(m, "aarch64") == 0) m = "arm64";
            snprintf(cls, sizeof(cls), "linux-%s", m);
        }
        s_cfg.device_class = strdup(cls);
    }

    int rc = 0;
    if (s_cfg.state_dir && kp_linux_mkdirs(s_cfg.state_dir, 0750) != 0) rc = -1;
    if (s_cfg.runtime_dir && kp_linux_mkdirs(s_cfg.runtime_dir, 0750) != 0) rc = -1;
    if (s_cfg.ota_staging_dir && kp_linux_mkdirs(s_cfg.ota_staging_dir, 0750) != 0) rc = -1;
    return rc;
}

//------------------------------------------------------------------------------
// Allocation
//------------------------------------------------------------------------------

void* kp_malloc(size_t size) { return malloc(size); }
void* kp_calloc(size_t n, size_t size) { return calloc(n, size); }
void  kp_free(void* ptr) { free(ptr); }

//------------------------------------------------------------------------------
// Timed condition wait on the monotonic clock
//------------------------------------------------------------------------------

void kp_linux_cond_init(pthread_cond_t* cond) {
#if defined(__APPLE__)
    pthread_cond_init(cond, NULL);
#else
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(cond, &attr);
    pthread_condattr_destroy(&attr);
#endif
}

bool kp_linux_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex, uint32_t timeout_ms) {
    if (timeout_ms == KP_WAIT_FOREVER) {
        return pthread_cond_wait(cond, mutex) == 0;
    }
#if defined(__APPLE__)
    struct timespec rel = { .tv_sec = timeout_ms / 1000, .tv_nsec = (long)(timeout_ms % 1000) * 1000000L };
    return pthread_cond_timedwait_relative_np(cond, mutex, &rel) == 0;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return pthread_cond_timedwait(cond, mutex, &ts) == 0;
#endif
}

//------------------------------------------------------------------------------
// Mutex / semaphore: a flag, a lock and a condition
//------------------------------------------------------------------------------

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool available;
} flag_t;

static flag_t* flag_create(bool available) {
    flag_t* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    pthread_mutex_init(&f->lock, NULL);
    kp_linux_cond_init(&f->cond);
    f->available = available;
    return f;
}

static bool flag_take(flag_t* f, uint32_t timeout_ms) {
    if (!f) return false;
    const int64_t deadline_us = (timeout_ms == KP_WAIT_FOREVER)
        ? 0 : kp_monotonic_us() + (int64_t)timeout_ms * 1000;
    pthread_mutex_lock(&f->lock);
    while (!f->available) {
        uint32_t wait_ms = KP_WAIT_FOREVER;
        if (timeout_ms != KP_WAIT_FOREVER) {
            const int64_t left_us = deadline_us - kp_monotonic_us();
            if (left_us <= 0) break;
            wait_ms = (uint32_t)((left_us + 999) / 1000);
        }
        kp_linux_cond_wait(&f->cond, &f->lock, wait_ms);
    }
    const bool got = f->available;
    if (got) f->available = false;
    pthread_mutex_unlock(&f->lock);
    return got;
}

static void flag_give(flag_t* f) {
    if (!f) return;
    pthread_mutex_lock(&f->lock);
    f->available = true;
    pthread_cond_signal(&f->cond);
    pthread_mutex_unlock(&f->lock);
}

static void flag_delete(flag_t* f) {
    if (!f) return;
    pthread_cond_destroy(&f->cond);
    pthread_mutex_destroy(&f->lock);
    free(f);
}

kp_mutex_t kp_mutex_create(void) { return (kp_mutex_t)flag_create(true); }
bool kp_mutex_take(kp_mutex_t m, uint32_t timeout_ms) { return flag_take((flag_t*)m, timeout_ms); }
void kp_mutex_give(kp_mutex_t m) { flag_give((flag_t*)m); }
void kp_mutex_delete(kp_mutex_t m) { flag_delete((flag_t*)m); }

kp_sem_t kp_sem_create(void) { return (kp_sem_t)flag_create(false); }
bool kp_sem_take(kp_sem_t s, uint32_t timeout_ms) { return flag_take((flag_t*)s, timeout_ms); }
void kp_sem_give(kp_sem_t s) { flag_give((flag_t*)s); }
void kp_sem_delete(kp_sem_t s) { flag_delete((flag_t*)s); }

//------------------------------------------------------------------------------
// Tasks
//------------------------------------------------------------------------------

typedef struct {
    kp_task_fn fn;
    void* arg;
    char name[16];
} task_launch_t;

static void* task_trampoline(void* arg) {
    task_launch_t launch = *(task_launch_t*)arg;
    free(arg);
#if defined(__APPLE__)
    pthread_setname_np(launch.name);
#else
    pthread_setname_np(pthread_self(), launch.name);
#endif
    launch.fn(launch.arg);
    return NULL;
}

// stack_bytes and priority are sized for an RTOS and are not used here: the
// thread gets the platform's default stack (OpenSSL, libcurl and the resolver
// need far more than an MCU task) and the default scheduling class.
bool kp_task_spawn(const char* name, kp_task_fn fn, void* arg,
    uint32_t stack_bytes, int priority) {
    (void)stack_bytes; (void)priority;
    task_launch_t* launch = calloc(1, sizeof(*launch));
    if (!launch) return false;
    launch->fn = fn;
    launch->arg = arg;
    snprintf(launch->name, sizeof(launch->name), "%s", name ? name : "koios");

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    const int rc = pthread_create(&thread, &attr, task_trampoline, launch);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        free(launch);
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------
// Timers: one thread, a list ordered by nothing (there are a dozen at most)
//------------------------------------------------------------------------------

struct kp_timer {
    struct kp_timer* next;
    kp_timer_fn cb;
    void* arg;
    int64_t deadline_us;  // valid while armed
    int64_t period_us;    // 0: one-shot
    bool armed;
    bool running;         // its callback is executing on the timer thread
};

static struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;       // wakes the timer thread
    pthread_cond_t idle_cond;  // a callback finished (kp_timer_delete waits on it)
    struct kp_timer* head;
    pthread_t thread;
    bool started;
} s_timers = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void* timer_thread(void* arg) {
    (void)arg;
#if defined(__APPLE__)
    pthread_setname_np("koios_timer");
#else
    pthread_setname_np(pthread_self(), "koios_timer");
#endif
    pthread_mutex_lock(&s_timers.lock);
    for (;;) {
        const int64_t now = kp_monotonic_us();
        struct kp_timer* due = NULL;
        int64_t next_us = -1;
        for (struct kp_timer* t = s_timers.head; t; t = t->next) {
            if (!t->armed) continue;
            if (t->deadline_us <= now) { due = t; break; }
            if (next_us < 0 || t->deadline_us < next_us) next_us = t->deadline_us;
        }

        if (due) {
            if (due->period_us > 0) {
                // Skip periods that were missed instead of firing a burst.
                due->deadline_us += due->period_us;
                if (due->deadline_us <= now) due->deadline_us = now + due->period_us;
            }
            else {
                due->armed = false;
            }
            due->running = true;
            const kp_timer_fn cb = due->cb;
            void* cb_arg = due->arg;
            pthread_mutex_unlock(&s_timers.lock);
            cb(cb_arg);
            pthread_mutex_lock(&s_timers.lock);
            due->running = false;
            pthread_cond_broadcast(&s_timers.idle_cond);
            continue;
        }

        if (next_us < 0) {
            kp_linux_cond_wait(&s_timers.cond, &s_timers.lock, KP_WAIT_FOREVER);
        }
        else {
            const int64_t wait_us = next_us - now;
            kp_linux_cond_wait(&s_timers.cond, &s_timers.lock, (uint32_t)((wait_us + 999) / 1000));
        }
    }
    return NULL;
}

// Caller holds s_timers.lock.
static bool timers_start_locked(void) {
    if (s_timers.started) return true;
    kp_linux_cond_init(&s_timers.cond);
    kp_linux_cond_init(&s_timers.idle_cond);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    const int rc = pthread_create(&s_timers.thread, &attr, timer_thread, NULL);
    pthread_attr_destroy(&attr);
    s_timers.started = (rc == 0);
    return s_timers.started;
}

kp_timer_t kp_timer_create(const char* name, kp_timer_fn cb, void* arg) {
    (void)name;
    if (!cb) return NULL;
    struct kp_timer* t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->cb = cb;
    t->arg = arg;
    pthread_mutex_lock(&s_timers.lock);
    if (!timers_start_locked()) {
        pthread_mutex_unlock(&s_timers.lock);
        free(t);
        return NULL;
    }
    t->next = s_timers.head;
    s_timers.head = t;
    pthread_mutex_unlock(&s_timers.lock);
    return t;
}

static void timer_arm(kp_timer_t t, int64_t delay_us, int64_t period_us) {
    if (!t) return;
    if (delay_us < 0) delay_us = 0;
    pthread_mutex_lock(&s_timers.lock);
    t->deadline_us = kp_monotonic_us() + delay_us;
    t->period_us = period_us;
    t->armed = true;
    pthread_cond_signal(&s_timers.cond);
    pthread_mutex_unlock(&s_timers.lock);
}

void kp_timer_start_once(kp_timer_t t, int64_t delay_us) {
    timer_arm(t, delay_us, 0);
}

void kp_timer_start_periodic(kp_timer_t t, int64_t period_us) {
    if (period_us <= 0) return;
    timer_arm(t, period_us, period_us);
}

void kp_timer_stop(kp_timer_t t) {
    if (!t) return;
    pthread_mutex_lock(&s_timers.lock);
    t->armed = false;
    pthread_mutex_unlock(&s_timers.lock);
}

void kp_timer_delete(kp_timer_t t) {
    if (!t) return;
    pthread_mutex_lock(&s_timers.lock);
    t->armed = false;
    // Wait for a callback in flight, unless we are that callback.
    while (t->running && !pthread_equal(pthread_self(), s_timers.thread)) {
        kp_linux_cond_wait(&s_timers.idle_cond, &s_timers.lock, KP_WAIT_FOREVER);
    }
    for (struct kp_timer** p = &s_timers.head; *p; p = &(*p)->next) {
        if (*p == t) { *p = t->next; break; }
    }
    pthread_mutex_unlock(&s_timers.lock);
    free(t);
}

//------------------------------------------------------------------------------
// Time, randomness, restart
//------------------------------------------------------------------------------

int64_t kp_monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

int64_t kp_wall_time_s(void) {
    return (int64_t)time(NULL);
}

uint32_t kp_random(void) {
    uint32_t v = 0;
    if (getentropy(&v, sizeof(v)) != 0) {
        // No entropy source: jitter only needs to differ between devices.
        v = (uint32_t)kp_monotonic_us() ^ (uint32_t)getpid();
    }
    return v;
}

void kp_delay_ms(uint32_t ms) {
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

// "Restart the device" means restart this process: its supervisor (systemd,
// Restart=always) starts it again, and the restart counters in runtime_dir
// carry over. The machine itself is never rebooted from here.
void kp_system_restart(void) {
    if (s_cfg.restart_handler) {
        s_cfg.restart_handler();
        return;
    }
    // _exit, not exit: this runs on one of the SDK's threads while the others
    // are still inside OpenSSL and libcurl, and exit() would run their
    // library teardown under them. The log ring is a shared mapping and needs
    // no flush; stdio does.
    fflush(NULL);
    _exit(KOIOS_LINUX_EXIT_RESTART);
}

//------------------------------------------------------------------------------
// Restart-surviving slots: a small file in runtime_dir (a tmpfs, so a reboot
// clears them, as a power cycle does on an MCU). Memory only without one.
//------------------------------------------------------------------------------

static uint32_t s_persist_ram[KP_PERSIST_SLOTS];

static bool persist_path(char* out, size_t out_size) {
    if (!s_cfg.runtime_dir) return false;
    return snprintf(out, out_size, "%s/persist", s_cfg.runtime_dir) < (int)out_size;
}

// Caller holds s_persist_lock.
static void persist_load(uint32_t slots[KP_PERSIST_SLOTS]) {
    memcpy(slots, s_persist_ram, sizeof(s_persist_ram));
    char path[560];
    if (!persist_path(path, sizeof(path))) return;
    FILE* f = fopen(path, "rb");
    if (!f) return;
    uint32_t tmp[KP_PERSIST_SLOTS];
    if (fread(tmp, sizeof(tmp), 1, f) == 1) memcpy(slots, tmp, sizeof(tmp));
    fclose(f);
}

uint32_t kp_persist_get(unsigned slot) {
    if (slot >= KP_PERSIST_SLOTS) return 0;
    uint32_t slots[KP_PERSIST_SLOTS];
    pthread_mutex_lock(&s_persist_lock);
    persist_load(slots);
    pthread_mutex_unlock(&s_persist_lock);
    return slots[slot];
}

void kp_persist_set(unsigned slot, uint32_t value) {
    if (slot >= KP_PERSIST_SLOTS) return;
    uint32_t slots[KP_PERSIST_SLOTS];
    pthread_mutex_lock(&s_persist_lock);
    persist_load(slots);
    if (slots[slot] != value) {
        slots[slot] = value;
        memcpy(s_persist_ram, slots, sizeof(slots));
        char path[560], tmp[580];
        if (persist_path(path, sizeof(path))) {
            snprintf(tmp, sizeof(tmp), "%s.tmp", path);
            FILE* f = fopen(tmp, "wb");
            if (f) {
                const bool ok = fwrite(slots, sizeof(slots), 1, f) == 1;
                if (fclose(f) == 0 && ok) rename(tmp, path);
                else remove(tmp);
            }
        }
    }
    pthread_mutex_unlock(&s_persist_lock);
}
