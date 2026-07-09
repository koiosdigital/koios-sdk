#pragma once

// OS primitives port. The core never touches FreeRTOS/POSIX directly; a port
// implements these against its RTOS. All timeouts are milliseconds.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KP_WAIT_FOREVER 0xFFFFFFFFu

// Large-buffer allocator. Ports decide placement (e.g. SPIRAM on ESP32);
// the core routes every message-sized allocation through these.
void* kp_malloc(size_t size);
void* kp_calloc(size_t n, size_t size);
void  kp_free(void* ptr);

typedef struct kp_mutex* kp_mutex_t;
kp_mutex_t kp_mutex_create(void);
bool kp_mutex_take(kp_mutex_t m, uint32_t timeout_ms);
void kp_mutex_give(kp_mutex_t m);
void kp_mutex_delete(kp_mutex_t m);

// Binary semaphore, created empty.
typedef struct kp_sem* kp_sem_t;
kp_sem_t kp_sem_create(void);
bool kp_sem_take(kp_sem_t s, uint32_t timeout_ms);
void kp_sem_give(kp_sem_t s);
void kp_sem_delete(kp_sem_t s);

// Detached task. The port reclaims the task when fn returns.
typedef void (*kp_task_fn)(void* arg);
bool kp_task_spawn(const char* name, kp_task_fn fn, void* arg,
                   uint32_t stack_bytes, int priority);

// One-shot / periodic software timers. Callbacks run in the port's timer
// context; keep them short and never block in them.
typedef struct kp_timer* kp_timer_t;
typedef void (*kp_timer_fn)(void* arg);
kp_timer_t kp_timer_create(const char* name, kp_timer_fn cb, void* arg);
void kp_timer_start_once(kp_timer_t t, int64_t delay_us);
void kp_timer_start_periodic(kp_timer_t t, int64_t period_us);
void kp_timer_stop(kp_timer_t t);
void kp_timer_delete(kp_timer_t t);

int64_t  kp_monotonic_us(void);
// Unix epoch seconds; may be far in the past before clock sync.
int64_t  kp_wall_time_s(void);
uint32_t kp_random(void);
void     kp_delay_ms(uint32_t ms);
void     kp_system_restart(void);

#ifdef __cplusplus
}
#endif
