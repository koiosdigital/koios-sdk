// System metrics on ESP-IDF: heap figures, task count, uptime, Wi-Fi signal
// strength and the reset reason. CPU load is reported when the firmware
// builds FreeRTOS with run-time statistics
// (CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS); the chip temperature is not read
// here, because the temperature sensor is a driver the application may own
// (publish it with koios_metrics_gauge() if you have it).

#include "koios/port/kp_metrics.h"

#include "sdkconfig.h"

#if CONFIG_KOIOS_SDK_METRICS_ENABLE

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_wifi.h>

#include <stdio.h>
#include <string.h>

static const char* reset_reason_name(esp_reset_reason_t reason) {
    switch (reason) {
    case ESP_RST_POWERON:    return "poweron";
    case ESP_RST_EXT:        return "external";
    case ESP_RST_SW:         return "software";
    case ESP_RST_PANIC:      return "panic";
    case ESP_RST_INT_WDT:    return "int_wdt";
    case ESP_RST_TASK_WDT:   return "task_wdt";
    case ESP_RST_WDT:        return "wdt";
    case ESP_RST_DEEPSLEEP:  return "deepsleep";
    case ESP_RST_BROWNOUT:   return "brownout";
    case ESP_RST_SDIO:       return "sdio";
    case ESP_RST_USB:        return "usb";
    case ESP_RST_JTAG:       return "jtag";
    case ESP_RST_EFUSE:      return "efuse";
    case ESP_RST_PWR_GLITCH: return "power_glitch";
    case ESP_RST_CPU_LOCKUP: return "cpu_lockup";
    default:                 return "unknown";
    }
}

#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
// Busy share of all cores since the previous sample: the idle tasks' run time
// against the run-time counter, both in the counter's own unit.
static void sample_cpu(kp_metrics_sample_t* m) {
    static configRUN_TIME_COUNTER_TYPE last_idle, last_total;
    static bool valid;

    const configRUN_TIME_COUNTER_TYPE idle = ulTaskGetIdleRunTimeCounter();
    const configRUN_TIME_COUNTER_TYPE total = portGET_RUN_TIME_COUNTER_VALUE();
    if (valid && total > last_total && idle >= last_idle) {
        const double window = (double)(total - last_total) * portNUM_PROCESSORS;
        double pct = 100.0 - 100.0 * (double)(idle - last_idle) / window;
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        m->cpu_pct = (float)pct;
        m->fields |= KP_METRIC_CPU_PCT;
    }
    last_idle = idle;
    last_total = total;
    valid = true;
}
#endif

void kp_metrics_sample(kp_metrics_sample_t* out) {
    memset(out, 0, sizeof(*out));

    out->uptime_s = (uint32_t)(esp_timer_get_time() / 1000000);
    out->fields |= KP_METRIC_UPTIME;

    out->cpu_cores = portNUM_PROCESSORS;
    out->fields |= KP_METRIC_CPU_CORES;
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    sample_cpu(out);
#endif

    // The default heap: internal RAM, plus PSRAM when malloc() may use it.
    out->mem_total_bytes = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
    out->mem_free_bytes = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    out->mem_min_free_bytes = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    out->mem_largest_block_bytes = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
    out->fields |= KP_METRIC_MEM | KP_METRIC_MEM_MIN_FREE | KP_METRIC_MEM_LARGEST;
#if CONFIG_SPIRAM
    // TLS handshakes and the Wi-Fi stack need internal RAM whatever PSRAM has left.
    out->mem_internal_free_bytes = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    out->fields |= KP_METRIC_MEM_INTERNAL;
#endif

    out->tasks = (uint32_t)uxTaskGetNumberOfTasks();
    out->fields |= KP_METRIC_TASKS;

    int rssi = 0;
    if (esp_wifi_sta_get_rssi(&rssi) == ESP_OK && rssi < 0) {
        out->net_rssi_dbm = (int16_t)rssi;
        out->fields |= KP_METRIC_NET_RSSI;
    }

    snprintf(out->reset_reason, sizeof(out->reset_reason), "%s",
        reset_reason_name(esp_reset_reason()));
    out->fields |= KP_METRIC_RESET_REASON;
}

#else  // !CONFIG_KOIOS_SDK_METRICS_ENABLE

void kp_metrics_sample(kp_metrics_sample_t* out) {
    (void)out;
}

#endif
