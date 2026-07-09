#include "koios/port/kp_os.h"

#include "sdkconfig.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <esp_random.h>
#include <esp_system.h>

#include <string.h>
#include <time.h>

//------------------------------------------------------------------------------
// Allocation — large buffers go to SPIRAM when configured
//------------------------------------------------------------------------------

#ifdef CONFIG_KOIOS_SDK_MALLOC_SPIRAM
#define KP_MALLOC_CAPS MALLOC_CAP_SPIRAM
#else
#define KP_MALLOC_CAPS MALLOC_CAP_DEFAULT
#endif

void* kp_malloc(size_t size) {
    return heap_caps_malloc(size, KP_MALLOC_CAPS);
}

void* kp_calloc(size_t n, size_t size) {
    return heap_caps_calloc(n, size, KP_MALLOC_CAPS);
}

void kp_free(void* ptr) {
    heap_caps_free(ptr);
}

//------------------------------------------------------------------------------
// Mutex / semaphore
//------------------------------------------------------------------------------

static TickType_t to_ticks(uint32_t timeout_ms) {
    return (timeout_ms == KP_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
}

kp_mutex_t kp_mutex_create(void) {
    return (kp_mutex_t)xSemaphoreCreateMutex();
}

bool kp_mutex_take(kp_mutex_t m, uint32_t timeout_ms) {
    return m && xSemaphoreTake((SemaphoreHandle_t)m, to_ticks(timeout_ms)) == pdTRUE;
}

void kp_mutex_give(kp_mutex_t m) {
    if (m) xSemaphoreGive((SemaphoreHandle_t)m);
}

void kp_mutex_delete(kp_mutex_t m) {
    if (m) vSemaphoreDelete((SemaphoreHandle_t)m);
}

kp_sem_t kp_sem_create(void) {
    return (kp_sem_t)xSemaphoreCreateBinary();
}

bool kp_sem_take(kp_sem_t s, uint32_t timeout_ms) {
    return s && xSemaphoreTake((SemaphoreHandle_t)s, to_ticks(timeout_ms)) == pdTRUE;
}

void kp_sem_give(kp_sem_t s) {
    if (s) xSemaphoreGive((SemaphoreHandle_t)s);
}

void kp_sem_delete(kp_sem_t s) {
    if (s) vSemaphoreDelete((SemaphoreHandle_t)s);
}

//------------------------------------------------------------------------------
// Tasks
//------------------------------------------------------------------------------

typedef struct {
    kp_task_fn fn;
    void* arg;
} task_launch_t;

static void task_trampoline(void* arg) {
    task_launch_t launch = *(task_launch_t*)arg;
    free(arg);
    launch.fn(launch.arg);
    vTaskDelete(NULL);
}

bool kp_task_spawn(const char* name, kp_task_fn fn, void* arg,
    uint32_t stack_bytes, int priority) {
    task_launch_t* launch = malloc(sizeof(task_launch_t));
    if (!launch) return false;
    launch->fn = fn;
    launch->arg = arg;

    if (xTaskCreate(task_trampoline, name, stack_bytes, launch,
        (UBaseType_t)priority, NULL) != pdPASS) {
        free(launch);
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------
// Timers
//------------------------------------------------------------------------------

kp_timer_t kp_timer_create(const char* name, kp_timer_fn cb, void* arg) {
    esp_timer_create_args_t args = {
        .callback = cb,
        .arg = arg,
        .dispatch_method = ESP_TIMER_TASK,
        .name = name,
        .skip_unhandled_events = true,
    };
    esp_timer_handle_t handle = NULL;
    if (esp_timer_create(&args, &handle) != ESP_OK) return NULL;
    return (kp_timer_t)handle;
}

void kp_timer_start_once(kp_timer_t t, int64_t delay_us) {
    if (t) esp_timer_start_once((esp_timer_handle_t)t, delay_us);
}

void kp_timer_start_periodic(kp_timer_t t, int64_t period_us) {
    if (t) esp_timer_start_periodic((esp_timer_handle_t)t, period_us);
}

void kp_timer_stop(kp_timer_t t) {
    if (t) esp_timer_stop((esp_timer_handle_t)t);
}

void kp_timer_delete(kp_timer_t t) {
    if (t) {
        esp_timer_stop((esp_timer_handle_t)t);
        esp_timer_delete((esp_timer_handle_t)t);
    }
}

//------------------------------------------------------------------------------
// Misc
//------------------------------------------------------------------------------

int64_t kp_monotonic_us(void) {
    return esp_timer_get_time();
}

int64_t kp_wall_time_s(void) {
    return (int64_t)time(NULL);
}

uint32_t kp_random(void) {
    return esp_random();
}

void kp_delay_ms(uint32_t ms) {
    vTaskDelay(pdMS_TO_TICKS(ms));
}

void kp_system_restart(void) {
    esp_restart();
}
