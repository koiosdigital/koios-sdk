// WebSocket port over esp_websocket_client. Handles TLS (server via cert
// bundle, client via cert + DS-peripheral key context or bearer header) and
// reassembles fragmented frames so the core only sees complete messages.

#include "koios/port/kp_websocket.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"

#include "sdkconfig.h"

#include <esp_websocket_client.h>
#include <esp_crt_bundle.h>
#include <esp_heap_caps.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <stdio.h>
#include <string.h>

static const char* TAG = "kp_ws";

struct kp_ws {
    esp_websocket_client_handle_t client;
    kp_ws_event_fn on_event;
    void* event_arg;
    size_t max_rx_size;
    char* headers;  // "Authorization: Bearer ...\r\n" or NULL

    // Fragment reassembly
    uint8_t* rx_buf;
    size_t rx_len;
    size_t rx_expected;
    bool rx_is_text;
};

static void rx_reset(struct kp_ws* ws) {
    if (ws->rx_buf) {
        kp_free(ws->rx_buf);
        ws->rx_buf = NULL;
    }
    ws->rx_len = ws->rx_expected = 0;
}

static void ws_event_handler(void* arg, esp_event_base_t base, int32_t event_id, void* event_data) {
    (void)base;
    struct kp_ws* ws = (struct kp_ws*)arg;
    esp_websocket_event_data_t* data = (esp_websocket_event_data_t*)event_data;

    switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED:
        ws->on_event(ws->event_arg, KP_WS_EV_CONNECTED, NULL, 0);
        break;

    case WEBSOCKET_EVENT_DISCONNECTED:
    case WEBSOCKET_EVENT_CLOSED:
    case WEBSOCKET_EVENT_ERROR:
        KP_LOGW(TAG, "Disconnected/error (event=%ld)", (long)event_id);
        rx_reset(ws);
        ws->on_event(ws->event_arg, KP_WS_EV_DISCONNECTED, NULL, 0);
        break;

    case WEBSOCKET_EVENT_DATA:
        if (data->op_code >= 0x08) break;  // control frames
        if (data->payload_len == 0 || data->data_ptr == NULL) break;

        if (data->payload_offset == 0) {
            rx_reset(ws);
            if ((size_t)data->payload_len > ws->max_rx_size) {
                KP_LOGE(TAG, "Message too large: %d", data->payload_len);
                break;
            }
            ws->rx_buf = kp_calloc(data->payload_len, 1);
            if (!ws->rx_buf) {
                KP_LOGE(TAG, "Alloc failed: %d bytes", data->payload_len);
                break;
            }
            ws->rx_expected = data->payload_len;
            ws->rx_is_text = (data->op_code == 0x01);
        }

        if (ws->rx_buf && ws->rx_len + data->data_len <= ws->rx_expected) {
            memcpy(ws->rx_buf + ws->rx_len, data->data_ptr, data->data_len);
            ws->rx_len += data->data_len;
        }

        if (ws->rx_buf && ws->rx_len >= ws->rx_expected) {
            uint8_t* msg = ws->rx_buf;
            size_t len = ws->rx_len;
            ws->rx_buf = NULL;
            ws->rx_len = ws->rx_expected = 0;

            ws->on_event(ws->event_arg,
                ws->rx_is_text ? KP_WS_EV_MSG_TEXT : KP_WS_EV_MSG_BINARY,
                msg, len);
            kp_free(msg);
        }
        break;

    default:
        break;
    }
}

kp_ws_t kp_ws_open(const kp_ws_config_t* cfg) {
    if (!cfg || !cfg->url || !cfg->on_event) return NULL;

    struct kp_ws* ws = calloc(1, sizeof(struct kp_ws));
    if (!ws) return NULL;
    ws->on_event = cfg->on_event;
    ws->event_arg = cfg->event_arg;
    ws->max_rx_size = cfg->max_rx_size ? cfg->max_rx_size : (16 * 1024);

    esp_websocket_client_config_t ws_cfg = { 0 };
    ws_cfg.uri = cfg->url;
    ws_cfg.crt_bundle_attach = esp_crt_bundle_attach;
    ws_cfg.network_timeout_ms = 15000;
    ws_cfg.buffer_size = 4096;
    // Cloudlink dispatches app callbacks (on_message / control frames) on
    // this task, so it needs app-work headroom on top of the TLS record
    // path — esp_websocket_client's 4 KB default overflows as soon as a
    // handler touches protobuf or NVS. Tunable per app via Kconfig.
    ws_cfg.task_stack = CONFIG_KOIOS_SDK_WS_TASK_STACK;
    ws_cfg.ping_interval_sec = 25;
    ws_cfg.pingpong_timeout_sec = 60;

    ws_cfg.keep_alive_enable = true;
    ws_cfg.keep_alive_idle = 10;
    ws_cfg.keep_alive_interval = 5;
    ws_cfg.keep_alive_count = 5;

    // The core owns reconnect policy.
    ws_cfg.disable_auto_reconnect = true;
    ws_cfg.enable_close_reconnect = false;

    if (cfg->client_cert_pem) {
        ws_cfg.client_cert = cfg->client_cert_pem;
        ws_cfg.client_cert_len = cfg->client_cert_len;
#ifdef CONFIG_ESP_TLS_USE_DS_PERIPHERAL
        ws_cfg.client_ds_data = cfg->client_key_ctx;
#endif
    }

    if (cfg->bearer) {
        size_t hlen = strlen("Authorization: Bearer \r\n") + strlen(cfg->bearer) + 1;
        ws->headers = malloc(hlen);
        if (!ws->headers) {
            free(ws);
            return NULL;
        }
        snprintf(ws->headers, hlen, "Authorization: Bearer %s\r\n", cfg->bearer);
        ws_cfg.headers = ws->headers;
    }

    ws->client = esp_websocket_client_init(&ws_cfg);
    if (!ws->client) {
        free(ws->headers);
        free(ws);
        return NULL;
    }

    esp_websocket_register_events(ws->client, WEBSOCKET_EVENT_ANY, ws_event_handler, ws);

    if (esp_websocket_client_start(ws->client) != ESP_OK) {
        esp_websocket_client_destroy(ws->client);
        free(ws->headers);
        free(ws);
        return NULL;
    }
    return ws;
}

bool kp_ws_is_connected(kp_ws_t ws) {
    return ws && ws->client && esp_websocket_client_is_connected(ws->client);
}

bool kp_ws_send(kp_ws_t ws, const void* data, size_t len, bool binary, uint32_t timeout_ms) {
    if (!ws || !ws->client) return false;
    if (!esp_websocket_client_is_connected(ws->client)) return false;

    const char* p = (const char*)data;
    int sent = binary
        ? esp_websocket_client_send_bin(ws->client, p, len, pdMS_TO_TICKS(timeout_ms))
        : esp_websocket_client_send_text(ws->client, p, len, pdMS_TO_TICKS(timeout_ms));
    return sent >= 0;
}

void kp_ws_close(kp_ws_t ws) {
    if (!ws) return;
    if (ws->client) {
        esp_websocket_client_destroy(ws->client);
        ws->client = NULL;
    }
    rx_reset(ws);
    free(ws->headers);
    free(ws);
}
