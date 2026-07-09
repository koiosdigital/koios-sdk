#pragma once

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KP_LOG_ERROR,
    KP_LOG_WARN,
    KP_LOG_INFO,
    KP_LOG_DEBUG,
} kp_log_level_t;

void kp_log_write(kp_log_level_t level, const char* tag, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

#define KP_LOGE(tag, ...) kp_log_write(KP_LOG_ERROR, tag, __VA_ARGS__)
#define KP_LOGW(tag, ...) kp_log_write(KP_LOG_WARN, tag, __VA_ARGS__)
#define KP_LOGI(tag, ...) kp_log_write(KP_LOG_INFO, tag, __VA_ARGS__)
#define KP_LOGD(tag, ...) kp_log_write(KP_LOG_DEBUG, tag, __VA_ARGS__)

#ifdef __cplusplus
}
#endif
