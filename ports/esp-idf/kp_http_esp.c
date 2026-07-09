// Buffered GET over kd_common's shared HTTP client, preserving the app-wide
// serialization of TLS sessions (one handshake in flight at a time).

#include "koios/port/kp_http.h"

#include <esp_http_client.h>
#include <kd_http.h>

#include <string.h>

typedef struct {
    char* buf;
    size_t buf_size;
    size_t len;
} response_ctx_t;

static esp_err_t http_event_handler(esp_http_client_event_t* evt) {
    if (!evt || !evt->user_data) return ESP_OK;
    response_ctx_t* ctx = (response_ctx_t*)evt->user_data;

    switch (evt->event_id) {
    case HTTP_EVENT_ON_CONNECTED:
        ctx->len = 0;
        ctx->buf[0] = '\0';
        break;
    case HTTP_EVENT_ON_DATA:
        if (evt->data && evt->data_len > 0) {
            size_t available = ctx->buf_size - ctx->len - 1;
            size_t to_copy = ((size_t)evt->data_len < available)
                ? (size_t)evt->data_len : available;
            if (to_copy > 0) {
                memcpy(ctx->buf + ctx->len, evt->data, to_copy);
                ctx->len += to_copy;
                ctx->buf[ctx->len] = '\0';
            }
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

int kp_http_get(const char* url,
    const kp_http_header_t* headers, size_t header_count,
    char* buf, size_t buf_size,
    int* status_code) {
    if (!url || !buf || buf_size < 2 || !status_code) return -1;
    *status_code = 0;
    buf[0] = '\0';

    response_ctx_t ctx = { .buf = buf, .buf_size = buf_size, .len = 0 };

    esp_http_client_handle_t client = kd_http_acquire(url, http_event_handler, &ctx, 20000);
    if (!client) return -1;

    for (size_t i = 0; i < header_count; i++) {
        if (headers[i].key && headers[i].value) {
            kd_http_set_header(headers[i].key, headers[i].value);
        }
    }

    esp_err_t err = esp_http_client_perform(client);
    *status_code = esp_http_client_get_status_code(client);
    if (err != ESP_OK) {
        kd_http_invalidate();  // connection state unknown, start fresh next time
    }
    kd_http_release();

    return (err == ESP_OK) ? 0 : -1;
}
