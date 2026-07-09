#include "koios/cloudlink.h"
#include "koios/ota.h"

#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_net.h"
#include "koios/port/kp_identity.h"
#include "koios/port/kp_websocket.h"

#include <cJSON.h>
#include <string.h>
#include <stdio.h>

static const char* TAG = "cloudlink";

#define DEFAULT_MAX_MSG_SIZE (16 * 1024)
#define DEFAULT_QUEUE_DEPTH  8

#define MAX_SOCK_FAILURES_BEFORE_NET_RESET 8
#define MAX_NET_RESETS_BEFORE_RESTART      3

#define RECONNECT_BASE_DELAY_US (3000LL * 1000)
#define RECONNECT_MAX_DELAY_US  (60LL * 1000 * 1000)

#define WELCOME_TIMEOUT_US (15LL * 1000 * 1000)

#define TOKEN_REFRESH_MIN_INTERVAL_US (30LL * 1000 * 1000)
#define TOKEN_REFRESH_FALLBACK_US     (13LL * 60 * 1000 * 1000)

typedef enum {
    STATE_WAITING_NETWORK,
    STATE_WAITING_GATE,   // network up; identity / app gate not ready yet
    STATE_READY,          // may connect; between attempts
    STATE_CONNECTED,      // socket up (session ready once welcome arrives)
} link_state_t;

typedef struct {
    uint8_t* data;
    size_t len;
} queued_msg_t;

static struct {
    bool initialized;
    koios_cloudlink_config_t cfg;
    char* api_key;  // owned copy; may be replaced by a server-issued key

    link_state_t state;
    bool session_ready;
    bool disconnect_handled;

    kp_mutex_t ws_mutex;  // guards ws handle lifetime
    kp_ws_t ws;

    // Outbox ring, guarded by out_mutex. Entries are kp_malloc'd.
    kp_mutex_t out_mutex;
    queued_msg_t* outbox;
    size_t out_head, out_count;

    kp_sem_t ctl_sem;  // wakes the control task to (re)connect

    kp_timer_t reconnect_timer;
    kp_timer_t gate_timer;
    kp_timer_t welcome_timer;
    kp_timer_t token_timer;

    int backoff_level;
    int sock_failures;
    int net_resets;

    kp_mutex_t token_mutex;
    char* token;
    int64_t token_expires_at;
    int64_t last_refresh_req_us;

    // mTLS materials, fetched once and cached for the process lifetime.
    char* cert_pem;
    size_t cert_len;
    void* key_ctx;
} s;

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

static void notify_state(koios_cloud_state_t st) {
    if (s.cfg.on_state_change) s.cfg.on_state_change(st);
}

static int64_t next_reconnect_delay(void) {
    int shift = (s.backoff_level > 5) ? 5 : s.backoff_level;
    int64_t delay = RECONNECT_BASE_DELAY_US << shift;
    if (delay > RECONNECT_MAX_DELAY_US) delay = RECONNECT_MAX_DELAY_US;
    // +/- 20% jitter
    delay = delay * (80 + (kp_random() % 41)) / 100;
    return delay;
}

static void schedule_reconnect(void) {
    if (s.reconnect_timer) {
        kp_timer_stop(s.reconnect_timer);
        kp_timer_start_once(s.reconnect_timer, next_reconnect_delay());
    }
}

static bool ws_connected_locked_check(void) {
    if (!s.ws_mutex) return false;
    if (!kp_mutex_take(s.ws_mutex, 50)) return false;
    bool connected = s.ws && kp_ws_is_connected(s.ws);
    kp_mutex_give(s.ws_mutex);
    return connected;
}

static bool locked_send(const void* data, size_t len, bool binary) {
    if (!s.ws_mutex) return false;
    if (!kp_mutex_take(s.ws_mutex, 6000)) return false;
    bool ok = false;
    if (s.ws && kp_ws_is_connected(s.ws)) {
        ok = kp_ws_send(s.ws, data, len, binary, 5000);
    }
    kp_mutex_give(s.ws_mutex);
    return ok;
}

static void destroy_ws(void) {
    kp_ws_t victim = NULL;
    if (s.ws_mutex && kp_mutex_take(s.ws_mutex, 6000)) {
        victim = s.ws;
        s.ws = NULL;
        kp_mutex_give(s.ws_mutex);
    }
    if (victim) kp_ws_close(victim);
}

//------------------------------------------------------------------------------
// Outbox
//------------------------------------------------------------------------------

static bool outbox_push(uint8_t* data, size_t len) {
    if (!kp_mutex_take(s.out_mutex, 100)) return false;
    bool ok = false;
    if (s.out_count < s.cfg.queue_depth) {
        size_t idx = (s.out_head + s.out_count) % s.cfg.queue_depth;
        s.outbox[idx].data = data;
        s.outbox[idx].len = len;
        s.out_count++;
        ok = true;
    }
    kp_mutex_give(s.out_mutex);
    return ok;
}

static bool outbox_pop(queued_msg_t* out) {
    if (!kp_mutex_take(s.out_mutex, 100)) return false;
    bool ok = false;
    if (s.out_count > 0) {
        *out = s.outbox[s.out_head];
        s.out_head = (s.out_head + 1) % s.cfg.queue_depth;
        s.out_count--;
        ok = true;
    }
    kp_mutex_give(s.out_mutex);
    return ok;
}

static void outbox_flush(void) {
    if (!ws_connected_locked_check()) return;
    queued_msg_t msg;
    while (outbox_pop(&msg)) {
        if (msg.data) {
            locked_send(msg.data, msg.len, true);
            kp_free(msg.data);
        }
    }
}

static void outbox_drain_free(void) {
    queued_msg_t msg;
    while (outbox_pop(&msg)) kp_free(msg.data);
}

//------------------------------------------------------------------------------
// Device token
//------------------------------------------------------------------------------

static void store_token(const char* token, int64_t expires_at) {
    if (!token || !token[0]) return;

    if (!kp_mutex_take(s.token_mutex, 1000)) return;
    kp_free(s.token);
    size_t len = strlen(token) + 1;
    s.token = kp_malloc(len);
    if (s.token) memcpy(s.token, token, len);
    s.token_expires_at = expires_at;
    kp_mutex_give(s.token_mutex);

    // Refresh shortly before expiry when both clocks look sane; otherwise
    // fall back to a fixed cadence.
    int64_t delay_us = TOKEN_REFRESH_FALLBACK_US;
    int64_t now = kp_wall_time_s();
    if (expires_at > 1600000000 && now > 1600000000 && expires_at > now) {
        int64_t margin_s = (expires_at - now) - 120;
        if (margin_s < 30) margin_s = 30;
        if (margin_s > 14 * 60) margin_s = 14 * 60;
        delay_us = margin_s * 1000 * 1000;
    }
    if (s.token_timer) {
        kp_timer_stop(s.token_timer);
        kp_timer_start_once(s.token_timer, delay_us);
    }
}

//------------------------------------------------------------------------------
// Session / control frames
//------------------------------------------------------------------------------

static void on_session_ready(void) {
    if (s.session_ready) return;
    s.session_ready = true;
    if (s.welcome_timer) kp_timer_stop(s.welcome_timer);

    s.sock_failures = 0;
    s.net_resets = 0;
    s.backoff_level = 0;

    notify_state(KOIOS_CLOUD_STATE_READY);
    if (s.cfg.on_session_ready) s.cfg.on_session_ready();
    outbox_flush();
}

static void handle_control_frame(const char* data, size_t len) {
    cJSON* root = cJSON_ParseWithLength(data, len);
    if (!root) {
        KP_LOGW(TAG, "Unparseable control frame (%u bytes)", (unsigned)len);
        return;
    }

    const char* type = cJSON_GetStringValue(cJSON_GetObjectItem(root, "type"));
    if (!type) {
        KP_LOGW(TAG, "Control frame without type");
    }
    else if (strcmp(type, "welcome") == 0 || strcmp(type, "token") == 0) {
        const char* token = cJSON_GetStringValue(cJSON_GetObjectItem(root, "token"));
        cJSON* exp = cJSON_GetObjectItem(root, "expires_at");
        store_token(token, cJSON_IsNumber(exp) ? (int64_t)cJSON_GetNumberValue(exp) : 0);

        if (strcmp(type, "welcome") == 0) {
            const char* issued = cJSON_GetStringValue(cJSON_GetObjectItem(root, "api_key"));
            if (issued && issued[0]) {
                // Server minted a device key (API-key autocreate). Adopt it
                // for future attempts and let the app persist it.
                char* copy = kp_malloc(strlen(issued) + 1);
                if (copy) {
                    strcpy(copy, issued);
                    kp_free(s.api_key);
                    s.api_key = copy;
                }
                if (s.cfg.on_api_key_issued) s.cfg.on_api_key_issued(issued);
            }
            const char* tz = cJSON_GetStringValue(cJSON_GetObjectItem(root, "timezone"));
            if (tz && tz[0] && s.cfg.on_timezone) s.cfg.on_timezone(tz);

            on_session_ready();
        }
    }
    else if (strcmp(type, "twin.desired") == 0) {
        cJSON* version = cJSON_GetObjectItem(root, "version");
        if (cJSON_IsNumber(version)) {
            char ack[64];
            snprintf(ack, sizeof(ack), "{\"type\":\"twin.desired.ack\",\"version\":%lld}",
                (long long)cJSON_GetNumberValue(version));
            locked_send(ack, strlen(ack), false);
        }
    }
    else if (strcmp(type, "twin.report.ack") == 0) {
        // Nothing to do.
    }
    else if (strcmp(type, "twin.error") == 0) {
        const char* msg = cJSON_GetStringValue(cJSON_GetObjectItem(root, "message"));
        KP_LOGW(TAG, "twin.error: %s", msg ? msg : "?");
    }
    else if (strcmp(type, "ota.offer") == 0) {
        // Low-latency nudge from a new deployment; the OTA module re-checks
        // over HTTPS (no-op if koios_ota_init was never called).
        KP_LOGI(TAG, "ota.offer received, triggering update check");
        koios_ota_check_now();
    }
    else if (s.cfg.on_control) {
        s.cfg.on_control(data, len);
    }

    cJSON_Delete(root);
}

//------------------------------------------------------------------------------
// Connection state machine
//------------------------------------------------------------------------------

static bool gate_ready(void) {
    if (s.cfg.auth_mode == KOIOS_CLOUD_AUTH_MTLS && !kp_identity_ready()) return false;
    if (s.cfg.ready_gate && !s.cfg.ready_gate()) return false;
    return true;
}

static void try_advance_state(void) {
    switch (s.state) {
    case STATE_WAITING_NETWORK:
        break;

    case STATE_WAITING_GATE:
        if (gate_ready()) {
            if (s.gate_timer) kp_timer_stop(s.gate_timer);
            s.state = STATE_READY;
            notify_state(KOIOS_CLOUD_STATE_CONNECTING);
            schedule_reconnect();
        }
        break;

    case STATE_READY:
    case STATE_CONNECTED:
        break;
    }
}

static void handle_ws_disconnect(void) {
    if (s.welcome_timer) kp_timer_stop(s.welcome_timer);

    if (s.state == STATE_WAITING_NETWORK) return;
    if (s.disconnect_handled) return;
    s.disconnect_handled = true;

    const bool was_ready = (s.state == STATE_CONNECTED) && s.session_ready;
    s.state = STATE_READY;
    s.session_ready = false;

    if (was_ready) {
        if (s.cfg.on_disconnect) s.cfg.on_disconnect();
        notify_state(KOIOS_CLOUD_STATE_CONNECTING);
    }

    s.sock_failures++;
    s.backoff_level++;
    KP_LOGW(TAG, "Socket failure %d/%d (net resets: %d/%d)",
        s.sock_failures, MAX_SOCK_FAILURES_BEFORE_NET_RESET,
        s.net_resets, MAX_NET_RESETS_BEFORE_RESTART);

    if (s.sock_failures >= MAX_SOCK_FAILURES_BEFORE_NET_RESET) {
        s.net_resets++;
        s.sock_failures = 0;

        if (s.net_resets >= MAX_NET_RESETS_BEFORE_RESTART) {
            KP_LOGE(TAG, "Too many network resets (%d), restarting", s.net_resets);
            kp_system_restart();
        }

        KP_LOGW(TAG, "Too many socket failures, resetting network (%d/%d)",
            s.net_resets, MAX_NET_RESETS_BEFORE_RESTART);
        kp_net_reset();
    }
    schedule_reconnect();
}

static void ws_event(void* arg, kp_ws_event_type_t ev, const uint8_t* data, size_t len) {
    (void)arg;
    switch (ev) {
    case KP_WS_EV_CONNECTED:
        s.state = STATE_CONNECTED;
        s.session_ready = false;
        if (s.welcome_timer) {
            kp_timer_stop(s.welcome_timer);
            kp_timer_start_once(s.welcome_timer, WELCOME_TIMEOUT_US);
        }
        break;

    case KP_WS_EV_DISCONNECTED:
        handle_ws_disconnect();
        break;

    case KP_WS_EV_MSG_TEXT:
        handle_control_frame((const char*)data, len);
        break;

    case KP_WS_EV_MSG_BINARY:
        if (s.cfg.on_message) s.cfg.on_message(data, len);
        outbox_flush();
        break;
    }
}

static int start_client(void) {
    if (s.ws) {
        KP_LOGW(TAG, "Client already exists, destroying first");
        destroy_ws();
    }
    s.disconnect_handled = false;

    kp_ws_config_t cfg = { 0 };
    cfg.url = s.cfg.url;
    cfg.max_rx_size = s.cfg.max_msg_size;
    cfg.on_event = ws_event;
    cfg.event_arg = NULL;

    if (s.cfg.auth_mode == KOIOS_CLOUD_AUTH_MTLS) {
        if (!s.cert_pem) {
            s.key_ctx = kp_identity_get_key_ctx();
            if (!s.key_ctx) {
                KP_LOGE(TAG, "Failed to get identity key context");
                return -1;
            }
            if (kp_identity_get_client_cert(&s.cert_pem, &s.cert_len) != 0) {
                KP_LOGE(TAG, "Failed to get device certificate");
                return -1;
            }
        }
        cfg.client_cert_pem = s.cert_pem;
        cfg.client_cert_len = s.cert_len + 1;  // include NUL for PEM parsing
        cfg.client_key_ctx = s.key_ctx;
    }
    else {
        cfg.bearer = s.api_key;
    }

    kp_ws_t ws = kp_ws_open(&cfg);
    if (!ws) return -1;

    if (!s.ws_mutex || !kp_mutex_take(s.ws_mutex, 6000)) {
        kp_ws_close(ws);
        return -1;
    }
    s.ws = ws;
    kp_mutex_give(s.ws_mutex);
    return 0;
}

// Control task: single place where clients are torn down and recreated.
static void ctl_task(void* arg) {
    (void)arg;
    for (;;) {
        if (!kp_sem_take(s.ctl_sem, KP_WAIT_FOREVER)) continue;
        if (!s.initialized) return;
        destroy_ws();
        if (s.state == STATE_READY) {
            if (start_client() != 0) {
                s.backoff_level++;
                schedule_reconnect();
            }
        }
    }
}

//------------------------------------------------------------------------------
// Timer / net callbacks
//------------------------------------------------------------------------------

static void reconnect_timer_cb(void* arg) {
    (void)arg;
    if (s.ctl_sem) kp_sem_give(s.ctl_sem);
}

static void gate_timer_cb(void* arg) {
    (void)arg;
    if (s.state == STATE_WAITING_GATE) {
        try_advance_state();
    }
    else {
        kp_timer_stop(s.gate_timer);
    }
}

static void welcome_timeout_cb(void* arg) {
    (void)arg;
    if (s.state == STATE_CONNECTED && !s.session_ready) {
        KP_LOGW(TAG, "No welcome frame within %llds, reconnecting",
            (long long)(WELCOME_TIMEOUT_US / 1000000));
        s.disconnect_handled = true;
        s.state = STATE_READY;
        s.backoff_level++;
        notify_state(KOIOS_CLOUD_STATE_CONNECTING);
        schedule_reconnect();
    }
}

static void token_timer_cb(void* arg) {
    (void)arg;
    koios_cloudlink_request_token_refresh();
}

static void net_on_connect(void) {
    if (s.state == STATE_WAITING_NETWORK) {
        s.state = STATE_WAITING_GATE;
        if (s.gate_timer) kp_timer_start_periodic(s.gate_timer, 1000 * 1000);
        try_advance_state();
    }
}

static void net_on_disconnect(void) {
    if (s.state != STATE_WAITING_NETWORK) {
        s.state = STATE_WAITING_NETWORK;
        notify_state(KOIOS_CLOUD_STATE_WAITING);
    }
}

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

void koios_cloudlink_init(const koios_cloudlink_config_t* config) {
    if (s.initialized || !config || !config->url || !config->on_message) {
        KP_LOGE(TAG, "Invalid init");
        return;
    }

    memset(&s, 0, sizeof(s));
    s.cfg = *config;
    if (s.cfg.max_msg_size == 0) s.cfg.max_msg_size = DEFAULT_MAX_MSG_SIZE;
    if (s.cfg.queue_depth == 0) s.cfg.queue_depth = DEFAULT_QUEUE_DEPTH;

    if (config->api_key) {
        s.api_key = kp_malloc(strlen(config->api_key) + 1);
        if (s.api_key) strcpy(s.api_key, config->api_key);
    }

    s.ws_mutex = kp_mutex_create();
    s.out_mutex = kp_mutex_create();
    s.token_mutex = kp_mutex_create();
    s.ctl_sem = kp_sem_create();
    s.outbox = kp_calloc(s.cfg.queue_depth, sizeof(queued_msg_t));

    if (!s.ws_mutex || !s.out_mutex || !s.token_mutex || !s.ctl_sem || !s.outbox) {
        KP_LOGE(TAG, "Failed to allocate primitives");
        return;
    }

    s.reconnect_timer = kp_timer_create("cl_reconn", reconnect_timer_cb, NULL);
    s.gate_timer = kp_timer_create("cl_gate", gate_timer_cb, NULL);
    s.welcome_timer = kp_timer_create("cl_welcome", welcome_timeout_cb, NULL);
    s.token_timer = kp_timer_create("cl_token", token_timer_cb, NULL);

    s.state = STATE_WAITING_NETWORK;
    s.initialized = true;

    if (!kp_task_spawn("cloudlink_ctl", ctl_task, NULL, 4096, 10)) {
        KP_LOGE(TAG, "Failed to spawn control task");
        s.initialized = false;
        return;
    }

    kp_net_subscribe(net_on_connect, net_on_disconnect);

    if (kp_net_is_connected()) {
        s.state = STATE_WAITING_GATE;
        if (s.gate_timer) kp_timer_start_periodic(s.gate_timer, 1000 * 1000);
        try_advance_state();
    }
    else {
        notify_state(KOIOS_CLOUD_STATE_WAITING);
    }
}

void koios_cloudlink_deinit(void) {
    if (!s.initialized) return;
    s.initialized = false;

    kp_timer_t timers[] = { s.token_timer, s.welcome_timer, s.reconnect_timer, s.gate_timer };
    for (size_t i = 0; i < sizeof(timers) / sizeof(timers[0]); i++) {
        if (timers[i]) {
            kp_timer_stop(timers[i]);
            kp_timer_delete(timers[i]);
        }
    }
    s.token_timer = s.welcome_timer = s.reconnect_timer = s.gate_timer = NULL;

    // Wake the control task so it observes !initialized and exits.
    if (s.ctl_sem) kp_sem_give(s.ctl_sem);
    kp_delay_ms(50);

    destroy_ws();
    outbox_drain_free();

    if (s.cert_pem) { kp_free(s.cert_pem); s.cert_pem = NULL; }
    if (s.key_ctx) { kp_identity_release_key_ctx(s.key_ctx); s.key_ctx = NULL; }

    if (s.token_mutex && kp_mutex_take(s.token_mutex, 1000)) {
        kp_free(s.token);
        s.token = NULL;
        kp_mutex_give(s.token_mutex);
    }
    kp_free(s.api_key);
    s.api_key = NULL;
    kp_free(s.outbox);
    s.outbox = NULL;

    if (s.ctl_sem) { kp_sem_delete(s.ctl_sem); s.ctl_sem = NULL; }
    if (s.token_mutex) { kp_mutex_delete(s.token_mutex); s.token_mutex = NULL; }
    if (s.out_mutex) { kp_mutex_delete(s.out_mutex); s.out_mutex = NULL; }
    if (s.ws_mutex) { kp_mutex_delete(s.ws_mutex); s.ws_mutex = NULL; }
}

bool koios_cloudlink_is_connected(void) {
    return ws_connected_locked_check();
}

bool koios_cloudlink_is_ready(void) {
    return s.session_ready && ws_connected_locked_check();
}

bool koios_cloudlink_send(const void* data, size_t len) {
    if (!s.initialized || !data || len == 0 || len > s.cfg.max_msg_size) return false;

    uint8_t* copy = kp_malloc(len);
    if (!copy) {
        KP_LOGE(TAG, "Failed to alloc %u bytes", (unsigned)len);
        return false;
    }
    memcpy(copy, data, len);

    if (!outbox_push(copy, len)) {
        KP_LOGW(TAG, "Outbox full");
        kp_free(copy);
        return false;
    }
    outbox_flush();
    return true;
}

bool koios_cloudlink_send_text(const char* text) {
    if (!s.initialized || !text) return false;
    return locked_send(text, strlen(text), false);
}

char* koios_cloudlink_get_token_copy(void) {
    if (!s.token_mutex) return NULL;
    if (!kp_mutex_take(s.token_mutex, 1000)) return NULL;

    char* copy = NULL;
    if (s.token) {
        size_t len = strlen(s.token) + 1;
        copy = kp_malloc(len);
        if (copy) memcpy(copy, s.token, len);
    }
    kp_mutex_give(s.token_mutex);
    return copy;
}

void koios_cloudlink_request_token_refresh(void) {
    int64_t now_us = kp_monotonic_us();
    if (s.last_refresh_req_us > 0 &&
        (now_us - s.last_refresh_req_us) < TOKEN_REFRESH_MIN_INTERVAL_US) {
        return;
    }
    if (koios_cloudlink_send_text("{\"type\":\"token.refresh\"}")) {
        s.last_refresh_req_us = now_us;
    }
}
