#pragma once

// Minimal buffered HTTP GET, sized for small JSON control responses (OTA
// manifest checks). Streaming/large transfers are out of scope — apps that
// need those keep using the platform client directly.

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* key;
    const char* value;
} kp_http_header_t;

// Perform a GET. The body is written into buf, NUL-terminated, truncated to
// buf_size - 1. Returns 0 when the request completed at the transport level
// (any HTTP status) and sets *status_code; returns nonzero on transport error.
int kp_http_get(const char* url,
                const kp_http_header_t* headers, size_t header_count,
                char* buf, size_t buf_size,
                int* status_code);

#ifdef __cplusplus
}
#endif
