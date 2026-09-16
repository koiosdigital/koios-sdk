// WebSocket port over esp_websocket_client. Handles TLS (server via cert
// bundle, client via cert + DS-peripheral key context or bearer header),
// reassembles fragmented frames so the core only sees complete messages,
// classifies every disconnect (link failure vs. server answered) and offers
// a bounded teardown so a blocked app callback cannot hang the core.

#include "koios/port/kp_websocket.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"

#include "sdkconfig.h"

#include <esp_websocket_client.h>
#include <esp_crt_bundle.h>
#include <esp_heap_caps.h>
#include <esp_tls_errors.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static const char* TAG = "kp_ws";

// Background teardown task (bounded close fallback). It only blocks on the
// client's stop handshake and frees memory; the stack covers
// esp_websocket_client_destroy's transport/event-loop cleanup and logging.
#define TEARDOWN_TASK_STACK 4096
#define TEARDOWN_TASK_PRIO  5

struct kp_ws {
    esp_websocket_client_handle_t client;
    kp_ws_event_fn on_event;
    void* event_arg;
    size_t max_rx_size;
    char* headers;  // "Authorization: Bearer ...\r\n" or NULL

    // Message reassembly. A message may span several frames (opcode 1/2,
    // then 0x0 continuations until FIN) and each frame may arrive as several
    // DATA events (payload_offset advancing through payload_len).
    uint8_t* rx_buf;
    size_t rx_cap;       // bytes allocated
    size_t rx_len;       // bytes received so far, all frames
    size_t rx_expected;  // rx_len at which the current frame is complete
    bool rx_active;      // a message is being assembled
    bool rx_is_text;

    // Per-attempt bookkeeping (transport task only).
    bool connected;             // CONNECTED seen for the current attempt
    bool disconnect_delivered;  // exactly one DISCONNECTED per attempt

    // Teardown. `closing` masks all events once close has been requested;
    // `owners` counts the closer and the background teardown task — the last
    // one to let go frees the struct.
    atomic_bool closing;
    atomic_int owners;
    SemaphoreHandle_t close_done;
};

//------------------------------------------------------------------------------
// Reassembly
//------------------------------------------------------------------------------

static void rx_reset(struct kp_ws* ws) {
    if (ws->rx_buf) {
        kp_free(ws->rx_buf);
        ws->rx_buf = NULL;
    }
    ws->rx_cap = ws->rx_len = ws->rx_expected = 0;
    ws->rx_active = false;
}

// Make room for `need` bytes total. Growth only happens for continuation
// frames (rare); the first frame allocates exactly its payload.
static bool rx_grow(struct kp_ws* ws, size_t need) {
    if (need <= ws->rx_cap) return true;
    uint8_t* buf = kp_malloc(need);
    if (!buf) return false;
    if (ws->rx_buf) {
        if (ws->rx_len) memcpy(buf, ws->rx_buf, ws->rx_len);
        kp_free(ws->rx_buf);
    }
    ws->rx_buf = buf;
    ws->rx_cap = need;
    return true;
}

static void handle_data(struct kp_ws* ws, const esp_websocket_event_data_t* data) {
    if (!data) return;
    const uint8_t op = data->op_code;
    if (op >= 0x08) return;                          // control frames (ping/pong/close)
    if (op != 0x00 && op != 0x01 && op != 0x02) return;  // reserved opcodes

    if (data->payload_offset == 0) {
        // First chunk of a frame. Opcode 1/2 opens a message; 0 continues one.
        if (op != 0x00) {
            rx_reset(ws);
            ws->rx_active = true;
            ws->rx_is_text = (op == 0x01);
        }
        else if (!ws->rx_active) {
            KP_LOGW(TAG, "Continuation frame without a start, dropping");
            return;
        }
        const size_t need = ws->rx_len + (size_t)data->payload_len;
        if (need > ws->max_rx_size) {
            KP_LOGE(TAG, "Message too large: %u > %u bytes",
                (unsigned)need, (unsigned)ws->max_rx_size);
            rx_reset(ws);
            return;
        }
        if (!rx_grow(ws, need)) {
            KP_LOGE(TAG, "Alloc failed: %u bytes", (unsigned)need);
            rx_reset(ws);
            return;
        }
        ws->rx_expected = need;
    }

    if (!ws->rx_active) return;  // frame is being dropped (too large / no start)

    if (data->data_len > 0 && data->data_ptr) {
        if (ws->rx_len + (size_t)data->data_len > ws->rx_expected) {
            KP_LOGE(TAG, "Frame overrun (%u + %d > %u), dropping message",
                (unsigned)ws->rx_len, data->data_len, (unsigned)ws->rx_expected);
            rx_reset(ws);
            return;
        }
        memcpy(ws->rx_buf + ws->rx_len, data->data_ptr, (size_t)data->data_len);
        ws->rx_len += (size_t)data->data_len;
    }

    // The frame is complete once every byte announced in its header is in;
    // the message is complete once a frame with FIN has been completed.
    if (ws->rx_len >= ws->rx_expected && data->fin) {
        uint8_t* msg = ws->rx_buf;
        const size_t len = ws->rx_len;
        const bool is_text = ws->rx_is_text;
        ws->rx_buf = NULL;
        ws->rx_cap = ws->rx_len = ws->rx_expected = 0;
        ws->rx_active = false;

        if (msg && len > 0) {
            ws->on_event(ws->event_arg,
                is_text ? KP_WS_EV_MSG_TEXT : KP_WS_EV_MSG_BINARY, msg, len);
        }
        kp_free(msg);
    }
}

//------------------------------------------------------------------------------
// Disconnect classification
//------------------------------------------------------------------------------

// esp-tls records mbedTLS codes as their positive magnitude (-ret).
static bool tls_stack_is_link_error(int code) {
    if (code < 0) code = -code;
    switch (code) {
    case -MBEDTLS_ERR_NET_SOCKET_FAILED:
    case -MBEDTLS_ERR_NET_CONNECT_FAILED:
    case -MBEDTLS_ERR_NET_RECV_FAILED:
    case -MBEDTLS_ERR_NET_SEND_FAILED:
    case -MBEDTLS_ERR_NET_UNKNOWN_HOST:
    case -MBEDTLS_ERR_NET_POLL_FAILED:
    case -MBEDTLS_ERR_SSL_TIMEOUT:
    case -MBEDTLS_ERR_SSL_WANT_READ:
    case -MBEDTLS_ERR_SSL_WANT_WRITE:
        return true;
    default:
        return false;  // alerts, bad records, EOF/close-notify, x509: the peer talked
    }
}

static kp_ws_fail_class_t classify(const esp_websocket_error_codes_t* e, bool clean_close,
                                   kp_ws_disconnect_info_t* info) {
    if (clean_close) return KP_WS_FAIL_SERVER;
    if (!e) return KP_WS_FAIL_UNKNOWN;

    info->handshake_status = e->esp_ws_handshake_status_code;
    info->tls_err = e->esp_tls_stack_err;
    info->sock_errno = e->esp_transport_sock_errno;

    if (e->error_type == WEBSOCKET_ERROR_TYPE_SERVER_CLOSE ||
        e->error_type == WEBSOCKET_ERROR_TYPE_HANDSHAKE) {
        return KP_WS_FAIL_SERVER;
    }
    if (e->error_type == WEBSOCKET_ERROR_TYPE_PONG_TIMEOUT) return KP_WS_FAIL_LINK;

    // The server answered the HTTP upgrade (401/403/503...): link is fine.
    if (e->esp_ws_handshake_status_code != 0) return KP_WS_FAIL_SERVER;
    // A certificate was presented and rejected: TLS-level answer.
    if (e->esp_tls_cert_verify_flags != 0) return KP_WS_FAIL_SERVER;

    switch (e->esp_tls_last_esp_err) {
    case ESP_ERR_ESP_TLS_CANNOT_RESOLVE_HOSTNAME:
    case ESP_ERR_ESP_TLS_CANNOT_CREATE_SOCKET:
    case ESP_ERR_ESP_TLS_UNSUPPORTED_PROTOCOL_FAMILY:
    case ESP_ERR_ESP_TLS_FAILED_CONNECT_TO_HOST:
    case ESP_ERR_ESP_TLS_SOCKET_SETOPT_FAILED:
    case ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT:
    case ESP_ERR_ESP_TLS_SERVER_HANDSHAKE_TIMEOUT:
        return KP_WS_FAIL_LINK;
    case ESP_ERR_ESP_TLS_TCP_CLOSED_FIN:
        return KP_WS_FAIL_SERVER;  // peer closed TCP cleanly: it is reachable
    default:
        break;
    }
    if (e->esp_tls_stack_err != 0) {
        return tls_stack_is_link_error(e->esp_tls_stack_err) ? KP_WS_FAIL_LINK : KP_WS_FAIL_SERVER;
    }

    switch (e->esp_transport_sock_errno) {
    case ECONNREFUSED:
    case ECONNRESET:
        return KP_WS_FAIL_SERVER;  // TCP answered (RST): the path to the host works
    case ETIMEDOUT:
    case EHOSTUNREACH:
    case ENETUNREACH:
    case ENETDOWN:
    case EAGAIN:
    case ENOTCONN:
    case EPIPE:
        return KP_WS_FAIL_LINK;
    default:
        break;
    }
    return (e->error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) ? KP_WS_FAIL_LINK : KP_WS_FAIL_UNKNOWN;
}

static const char* class_name(kp_ws_fail_class_t c) {
    switch (c) {
    case KP_WS_FAIL_LINK:   return "link";
    case KP_WS_FAIL_SERVER: return "server";
    default:                return "unknown";
    }
}

static void log_stack_watermark(const char* when) {
    // Runs on the transport task, so NULL means "this task".
    KP_LOGI(TAG, "WS task stack high-water mark at %s: %u bytes free",
        when, (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

static void deliver_disconnect(struct kp_ws* ws, const esp_websocket_event_data_t* data, bool clean_close) {
    rx_reset(ws);
    if (ws->disconnect_delivered) return;
    ws->disconnect_delivered = true;

    kp_ws_disconnect_info_t info = { 0 };
    info.was_connected = ws->connected;
    info.fail_class = classify(data ? &data->error_handle : NULL, clean_close, &info);
    ws->connected = false;

    KP_LOGW(TAG, "Disconnected (%s%s: handshake=%d tls=0x%x errno=%d)",
        class_name(info.fail_class), info.was_connected ? ", was connected" : "",
        info.handshake_status, (unsigned)(info.tls_err < 0 ? -info.tls_err : info.tls_err),
        info.sock_errno);
    log_stack_watermark("disconnect");

    ws->on_event(ws->event_arg, KP_WS_EV_DISCONNECTED,
        (const uint8_t*)&info, sizeof(info));
}

//------------------------------------------------------------------------------
// Event handler (transport task)
//------------------------------------------------------------------------------

static void ws_event_handler(void* arg, esp_event_base_t base, int32_t event_id, void* event_data) {
    (void)base;
    struct kp_ws* ws = (struct kp_ws*)arg;
    esp_websocket_event_data_t* data = (esp_websocket_event_data_t*)event_data;

    // Close requested (or the closer gave up waiting): the core has dropped
    // this handle and nobody listens any more.
    if (atomic_load(&ws->closing)) return;

    switch (event_id) {
    case WEBSOCKET_EVENT_BEFORE_CONNECT:
        ws->connected = false;
        ws->disconnect_delivered = false;
        break;

    case WEBSOCKET_EVENT_CONNECTED:
        ws->connected = true;
        ws->disconnect_delivered = false;
        ws->on_event(ws->event_arg, KP_WS_EV_CONNECTED, NULL, 0);
        break;

    case WEBSOCKET_EVENT_ERROR:
        // Informational only: it may be dispatched from the SENDER's task on
        // a write failure. The DISCONNECTED that follows (always on the
        // transport task) carries the classification the core acts on.
        KP_LOGD(TAG, "Transport error reported (type=%d)",
            data ? (int)data->error_handle.error_type : -1);
        break;

    case WEBSOCKET_EVENT_DISCONNECTED:
        deliver_disconnect(ws, data, false);
        break;

    case WEBSOCKET_EVENT_CLOSED:
        deliver_disconnect(ws, data, true);
        break;

    case WEBSOCKET_EVENT_FINISH:
        // Task exiting. An attempt that never produced DISCONNECTED (e.g.
        // the client stopped while closing) still owes the core exactly one.
        log_stack_watermark("finish");
        if (!ws->disconnect_delivered) deliver_disconnect(ws, data, false);
        break;

    case WEBSOCKET_EVENT_DATA:
        handle_data(ws, data);
        break;

    default:
        break;
    }
}

//------------------------------------------------------------------------------
// Lifecycle
//------------------------------------------------------------------------------

static void ws_free(struct kp_ws* ws) {
    rx_reset(ws);
    if (ws->close_done) vSemaphoreDelete(ws->close_done);
    free(ws->headers);
    free(ws);
}

static void ws_release(struct kp_ws* ws) {
    if (atomic_fetch_sub(&ws->owners, 1) == 1) ws_free(ws);
}

kp_ws_t kp_ws_open(const kp_ws_config_t* cfg) {
    if (!cfg || !cfg->url || !cfg->on_event) return NULL;

    struct kp_ws* ws = calloc(1, sizeof(struct kp_ws));
    if (!ws) return NULL;
    ws->on_event = cfg->on_event;
    ws->event_arg = cfg->event_arg;
    ws->max_rx_size = cfg->max_rx_size ? cfg->max_rx_size : (16 * 1024);
    atomic_init(&ws->closing, false);
    atomic_init(&ws->owners, 1);

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
    return ws && ws->client && !atomic_load(&ws->closing) &&
        esp_websocket_client_is_connected(ws->client);
}

bool kp_ws_send(kp_ws_t ws, const void* data, size_t len, bool binary, uint32_t timeout_ms) {
    if (!ws || !ws->client || atomic_load(&ws->closing)) return false;
    if (!esp_websocket_client_is_connected(ws->client)) return false;

    const char* p = (const char*)data;
    int sent = binary
        ? esp_websocket_client_send_bin(ws->client, p, (int)len, pdMS_TO_TICKS(timeout_ms))
        : esp_websocket_client_send_text(ws->client, p, (int)len, pdMS_TO_TICKS(timeout_ms));
    return sent == (int)len;
}

// Joins the client's task (may take as long as an app callback blocks it),
// then frees the client. Runs detached so the closer can stop waiting.
static void teardown_task(void* arg) {
    struct kp_ws* ws = (struct kp_ws*)arg;
    esp_websocket_client_destroy(ws->client);
    ws->client = NULL;
    xSemaphoreGive(ws->close_done);
    ws_release(ws);
    vTaskDelete(NULL);
}

bool kp_ws_close_bounded(kp_ws_t ws, uint32_t timeout_ms) {
    if (!ws) return true;
    // Mask events first: the core has dropped its handle and must not see
    // frames, a FINISH-synthesized DISCONNECTED, or anything else from the
    // victim while (or after) it is torn down.
    atomic_store(&ws->closing, true);

    if (!ws->client) {
        ws_free(ws);
        return true;
    }

    if (timeout_ms != KP_WAIT_FOREVER) {
        ws->close_done = xSemaphoreCreateBinary();
        if (ws->close_done) {
            atomic_store(&ws->owners, 2);  // closer + teardown task
            if (xTaskCreate(teardown_task, "kp_ws_close", TEARDOWN_TASK_STACK, ws,
                TEARDOWN_TASK_PRIO, NULL) == pdPASS) {
                const bool done = xSemaphoreTake(ws->close_done, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
                if (!done) {
                    KP_LOGE(TAG, "WS task did not exit within %u ms (app callback blocking?); "
                        "detaching, teardown continues in background", (unsigned)timeout_ms);
                }
                ws_release(ws);
                return done;
            }
            // Could not spawn: undo and fall back to a synchronous close.
            atomic_store(&ws->owners, 1);
        }
        KP_LOGW(TAG, "Bounded close unavailable, closing synchronously");
    }

    esp_websocket_client_destroy(ws->client);
    ws->client = NULL;
    ws_free(ws);
    return true;
}

void kp_ws_close(kp_ws_t ws) {
    kp_ws_close_bounded(ws, KP_WAIT_FOREVER);
}
