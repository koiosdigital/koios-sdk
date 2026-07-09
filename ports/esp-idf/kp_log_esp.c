#include "koios/port/kp_log.h"

#include <esp_log.h>
#include <stdio.h>

void kp_log_write(kp_log_level_t level, const char* tag, const char* fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    switch (level) {
    case KP_LOG_ERROR: ESP_LOGE(tag, "%s", buf); break;
    case KP_LOG_WARN:  ESP_LOGW(tag, "%s", buf); break;
    case KP_LOG_INFO:  ESP_LOGI(tag, "%s", buf); break;
    case KP_LOG_DEBUG: ESP_LOGD(tag, "%s", buf); break;
    }
}
