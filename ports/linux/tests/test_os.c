// kp_os on Linux: timed takes, timers, restart-surviving slots.

#include "check.h"

#include "koios/linux.h"
#include "koios/port/kp_os.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_int s_fired;
static kp_sem_t s_done;

static void on_timer(void* arg) {
    atomic_fetch_add(&s_fired, 1);
    if (arg) kp_sem_give((kp_sem_t)arg);
}

static void giver(void* arg) {
    kp_delay_ms(50);
    kp_sem_give((kp_sem_t)arg);
}

int main(int argc, char** argv) {
    const char* dir = argc > 1 ? argv[1] : "/tmp";
    const koios_linux_config_t cfg = { .runtime_dir = dir };
    CHECK_EQ(koios_linux_init(&cfg), 0);

    // A mutex is free when created, a semaphore is not.
    kp_mutex_t m = kp_mutex_create();
    CHECK(kp_mutex_take(m, 0));
    int64_t t0 = kp_monotonic_us();
    CHECK(!kp_mutex_take(m, 80));  // held: times out
    const int64_t waited = kp_monotonic_us() - t0;
    CHECK(waited >= 70 * 1000 && waited < 500 * 1000);
    kp_mutex_give(m);
    CHECK(kp_mutex_take(m, 0));
    kp_mutex_give(m);
    kp_mutex_delete(m);

    kp_sem_t sem = kp_sem_create();
    CHECK(!kp_sem_take(sem, 10));
    CHECK(kp_task_spawn("giver", giver, sem, 4096, 5));
    CHECK(kp_sem_take(sem, 2000));  // given from another thread
    CHECK(!kp_sem_take(sem, 0));    // binary: taken once

    // One-shot fires once; periodic keeps firing until stopped.
    s_done = kp_sem_create();
    kp_timer_t once = kp_timer_create("once", on_timer, s_done);
    kp_timer_start_once(once, 30 * 1000);
    CHECK(kp_sem_take(s_done, 2000));
    kp_delay_ms(100);
    CHECK_EQ(atomic_load(&s_fired), 1);

    atomic_store(&s_fired, 0);
    kp_timer_t periodic = kp_timer_create("periodic", on_timer, NULL);
    kp_timer_start_periodic(periodic, 20 * 1000);
    kp_delay_ms(250);
    kp_timer_stop(periodic);
    const int fired = atomic_load(&s_fired);
    CHECK(fired >= 6 && fired <= 14);
    kp_delay_ms(100);
    CHECK_EQ(atomic_load(&s_fired), fired);  // stopped means stopped

    // A stopped one-shot does not fire; re-arming replaces the deadline.
    atomic_store(&s_fired, 0);
    kp_timer_start_once(once, 50 * 1000);
    kp_timer_stop(once);
    kp_delay_ms(120);
    CHECK_EQ(atomic_load(&s_fired), 0);
    kp_timer_delete(once);
    kp_timer_delete(periodic);

    // Slots survive in runtime_dir (a second process reads them back).
    if (argc > 2 && strcmp(argv[2], "read") == 0) {
        CHECK_EQ(kp_persist_get(0), 7);
        CHECK_EQ(kp_persist_get(3), 0xDEADBEEFu);
    }
    else {
        kp_persist_set(0, 7);
        kp_persist_set(3, 0xDEADBEEFu);
        CHECK_EQ(kp_persist_get(0), 7);
        CHECK_EQ(kp_persist_get(1), 0);
        CHECK_EQ(kp_persist_get(99), 0);
    }

    // "Restart the device" ends this process with the status its supervisor
    // restarts on, and nothing else: no reboot, no signal.
    const pid_t child = fork();
    if (child == 0) {
        kp_system_restart();
        _exit(1);  // not reached
    }
    int status = 0;
    CHECK(child > 0 && waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), KOIOS_LINUX_EXIT_RESTART);

    CHECK(kp_random() != kp_random() || kp_random() != kp_random());
    CHECK(kp_wall_time_s() > 1600000000);
    CHECK_DONE();
}
