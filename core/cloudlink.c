#include "koios/cloudlink.h"
#include "koios/ota.h"

#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_net.h"
#include "koios/port/kp_identity.h"
#include "koios/port/kp_websocket.h"
#include "koios/port/kp_ota.h"

#include <cJSON.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

static const char* TAG = "cloudlink";

// Default inbound/outbound message bound. Apps raise it via
// koios_cloudlink_config_t::max_msg_size (Tranquil uses 32 KiB for pattern
// chunks); the outbox worst case is queue_depth x max_msg_size, logged at init.
#define DEFAULT_MAX_MSG_SIZE (16 * 1024)
#define DEFAULT_QUEUE_DEPTH  8

// Escalation is deliberately slow and only counts LINK failures — attempts
// where nothing answered (DNS, TCP connect, socket/pong timeout). A server
// that answers (HTTP status on the upgrade, TLS alert, cert rejection, close
// frame) proves the local link works: it resets the counter and never
// escalates. At the 60 s backoff cap, 30 link failures is ~30 min of the
// cloud being unreachable before the network is bounced, and six bounces
// before a restart. net_resets and the restart count live in reboot-
// persistent slots so a restart does not hand out a fresh cascade: after
// MAX_CLOUD_RESTARTS restarts less than RESTART_SERIES_WINDOW_S apart with no
// session in between, cloudlink stops restarting and just keeps backing off.
#define MAX_SOCK_FAILURES_BEFORE_NET_RESET 30
#define MAX_NET_RESETS_BEFORE_RESTART      6
#define MAX_CLOUD_RESTARTS                 3
#define RESTART_SERIES_WINDOW_S            (60 * 60)

// kp_persist slots (survive a software restart, not a power cycle)
#define PERSIST_SLOT_RESTARTS       0
#define PERSIST_SLOT_LAST_RESTART_S 1
#define PERSIST_SLOT_NET_RESETS     2

#define RECONNECT_BASE_DELAY_US (3000LL * 1000)
#define RECONNECT_MAX_DELAY_US  (60LL * 1000 * 1000)

#define WELCOME_TIMEOUT_US (15LL * 1000 * 1000)

#define TOKEN_REFRESH_MIN_INTERVAL_US (30LL * 1000 * 1000)
#define TOKEN_REFRESH_FALLBACK_US     (13LL * 60 * 1000 * 1000)
// Re-ask if no token arrived after a refresh request (request dropped,
// link flapped); store_token() re-arms the proper deadline on arrival.
#define TOKEN_REFRESH_RETRY_US        (60LL * 1000 * 1000)

// Text "ping" keepalive. Cloudflare DO hibernation auto-responds to TEXT
// "ping" with "pong" without waking the DO; protocol-level pings (opcode
// 0x9) are handled at the edge and don't count as DO activity, so the DO
// idles out after ~100 s. This timer sends a TEXT frame to keep it alive.
#define PING_INTERVAL_US              (30LL * 1000 * 1000)

// How long a teardown waits for the WS task before the port detaches it.
// Above the port's 15 s connect timeout so a legitimate in-flight handshake
// finishes; a blocked app callback is the only thing that trips it.
#define WS_CLOSE_TIMEOUT_MS 20000

// Link-state critical sections are tiny and never call out, so a take that
// fails is a bug elsewhere; log and skip the transition rather than block a
// timer/event task forever.
#define STATE_LOCK_TIMEOUT_MS 2000

// Anything before this is "clock not set".
#define WALL_TIME_SANE_S 1600000000LL

typedef enum {
    STATE_WAITING_NETWORK,
    STATE_WAITING_GATE,   // network up; identity / app gate not ready yet
    STATE_READY,          // may connect; between attempts
    STATE_CONNECTED,      // socket up (session ready once welcome arrives)
} link_state_t;

typedef struct {
    uint8_t* data;
    size_t len;
    bool binary;
} queued_msg_t;

typedef enum {
    WS_DESTROYED,  // client gone, its task joined
    WS_DETACHED,   // client gone from our point of view; task still unwinding
    WS_BUSY,       // ws_mutex starved: client still live, nothing done
} destroy_result_t;

static struct {
    bool initialized;
    koios_cloudlink_config_t cfg;
    char* api_key;  // owned copy; may be replaced by a server-issued key

    // Link state. Guarded by state_mutex: mutated from the WS task
    // (connect/disconnect/welcome), the timer task (welcome timeout, gate),
    // the net event task and the control task.
    kp_mutex_t state_mutex;
    link_state_t state;
    bool session_ready;
    bool disconnect_handled;
    int backoff_level;
    int sock_failures;        // consecutive LINK-class failures
    int net_resets;           // mirrored in PERSIST_SLOT_NET_RESETS
    bool connect_requested;   // reconnect timer fired: ctl task should (re)open
    bool escalate_requested;  // ctl task should run the failure cascade
    bool veto_logged;         // "policy vetoed" logged once per streak
    bool cap_logged;          // "restart cap reached" logged once per streak
    bool cert_refresh_requested; // cert renewed: clear cache and reconnect

    kp_mutex_t ws_mutex;  // guards ws handle lifetime
    kp_ws_t ws;

    // Outbox ring, guarded by out_mutex. Entries are kp_malloc'd. The head
    // may be "in flight" (being written by the sender task): it is never
    // dropped to make room and only removed once the write succeeded.
    kp_mutex_t out_mutex;
    queued_msg_t* outbox;
    size_t out_head, out_count;
    bool out_inflight;

    kp_sem_t ctl_sem;  // wakes the control task (connect / escalate / exit)
    kp_sem_t tx_sem;   // wakes the sender task to drain the outbox

    kp_timer_t reconnect_timer;
    kp_timer_t gate_timer;
    kp_timer_t welcome_timer;
    kp_timer_t token_timer;
    kp_timer_t ping_timer;

    kp_mutex_t token_mutex;
    char* token;
    int64_t token_expires_at;
    int64_t last_refresh_req_us;

    // Device UUID from the welcome frame (guarded by token_mutex).
    char device_id[48];

    // mTLS materials, fetched once and cached for the process lifetime.
    char* cert_pem;
    size_t cert_len;
    void* key_ctx;
} s;

// Restart policy lives outside `s`: it may be installed before init and
// must survive deinit/init cycles (cert renewal reinitializes the link).
static bool (*s_may_restart)(void* ctx);
static void* s_may_restart_ctx;

// Control-task exit handshake. Lives outside `s` because init() memsets the
// state struct; deinit() must positively observe the task's exit before any
// of the resources the task uses (cert, key ctx, mutexes) are freed.
// Starts true (no task yet) so the first init() is allowed; init() refuses to
// run while false — a stuck control task still references the state block.
static volatile bool s_ctl_task_exited = true;
// Same handshake for the sender task (see tx_task).
static volatile bool s_tx_task_exited = true;

// Public-API teardown gate. deinit() can run at any time (e.g. the cert-renew
// path reinitializes the link) while other tasks are inside send/is_ready —
// those touch the outbox array and mutexes that deinit frees. A bare
// `s.initialized` check is not enough: a sender that passed the check can
// straddle the teardown, write into the freed outbox (use-after-free), and
// then pop + kp_free garbage pointers — heap corruption. Entrants register in
// s_api_users; deinit sets s_teardown first, then waits for users to drain
// before freeing anything. Lives outside `s` for the same reason as above.
static atomic_bool s_teardown = true;
static atomic_int s_api_users;

// Set when deinit() could not fully join the WS client's task (ws_mutex
// starved past all retries, or the port had to detach a client whose task
// was still inside an app callback). That task may still reference the
// state block, so re-init (memset + fresh mutexes under it) is refused for
// the rest of the process lifetime.
static atomic_bool s_ws_orphaned;

static bool api_enter(void) {
    if (atomic_load(&s_teardown)) return false;
    atomic_fetch_add(&s_api_users, 1);
    // Re-check after registering: teardown may have started in between. The
    // drain loop in deinit() only proceeds once we either back out here or
    // finish the call, so past this point the state stays alive until exit.
    if (atomic_load(&s_teardown) || !s.initialized) {
        atomic_fetch_sub(&s_api_users, 1);
        return false;
    }
    return true;
}

static void api_exit(void) {
    atomic_fetch_sub(&s_api_users, 1);
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

static bool state_lock(void) {
    if (!s.state_mutex) return false;
    if (kp_mutex_take(s.state_mutex, STATE_LOCK_TIMEOUT_MS)) return true;
    KP_LOGE(TAG, "state_mutex held >%d ms, skipping transition", STATE_LOCK_TIMEOUT_MS);
    return false;
}

static void state_unlock(void) {
    kp_mutex_give(s.state_mutex);
}

static void notify_state(koios_cloud_state_t st) {
    if (s.cfg.on_state_change) s.cfg.on_state_change(st);
}

// Caller holds state_mutex.
static int64_t next_reconnect_delay_locked(void) {
    int shift = (s.backoff_level > 5) ? 5 : s.backoff_level;
    int64_t delay = RECONNECT_BASE_DELAY_US << shift;
    if (delay > RECONNECT_MAX_DELAY_US) delay = RECONNECT_MAX_DELAY_US;
    // +/- 20% jitter
    delay = delay * (80 + (kp_random() % 41)) / 100;
    return delay;
}

static void schedule_reconnect(void) {
    if (!s.reconnect_timer) return;
    int64_t delay = RECONNECT_BASE_DELAY_US;
    if (state_lock()) {
        delay = next_reconnect_delay_locked();
        state_unlock();
    }
    kp_timer_stop(s.reconnect_timer);
    kp_timer_start_once(s.reconnect_timer, delay);
}

static void bump_backoff(void) {
    if (state_lock()) {
        s.backoff_level++;
        state_unlock();
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

// Claims the client handle and tears it down with a bounded wait. WS_BUSY
// means the handle could not even be claimed (ws_mutex starved): the old
// client is still live and dispatching events, so callers MUST NOT free
// state or open a second client over it. WS_DETACHED means the port gave
// up waiting for the transport task (an app callback is blocking it): no
// more events reach us and the port reclaims the client in the background,
// but that task may still be inside cloudlink state for a while.
static destroy_result_t destroy_ws(void) {
    if (!s.ws_mutex) return WS_DESTROYED;  // no mutex -> no client was ever opened
    if (!kp_mutex_take(s.ws_mutex, 6000)) {
        KP_LOGE(TAG, "destroy_ws: ws_mutex held >6s, client NOT destroyed");
        return WS_BUSY;
    }
    kp_ws_t victim = s.ws;
    s.ws = NULL;
    kp_mutex_give(s.ws_mutex);
    if (!victim) return WS_DESTROYED;
    if (!kp_ws_close_bounded(victim, WS_CLOSE_TIMEOUT_MS)) {
        KP_LOGE(TAG, "WS client detached after %d ms (app callback blocking the WS task?)",
            WS_CLOSE_TIMEOUT_MS);
        return WS_DETACHED;
    }
    return WS_DESTROYED;
}

//------------------------------------------------------------------------------
// Outbox
//------------------------------------------------------------------------------

static bool outbox_push(uint8_t* data, size_t len, bool binary) {
    if (!kp_mutex_take(s.out_mutex, 100)) return false;
    bool ok = true;
    const size_t depth = s.cfg.queue_depth;
    if (s.out_count >= depth) {
        // Full: drop the OLDEST entry rather than the newest. The outbox only
        // fills while the link is down, and what is queued then is stale
        // telemetry; the newest message (typically the reconnect handshake)
        // is the one worth keeping. The head is exempt while the sender task
        // is writing it (freeing it under the write would be a use-after-free).
        const size_t victim_off = s.out_inflight ? 1 : 0;
        if (s.out_count <= victim_off) {
            ok = false;  // depth-1 outbox whose only entry is in flight
        }
        else {
            const size_t idx = (s.out_head + victim_off) % depth;
            KP_LOGW(TAG, "Outbox full, dropping oldest (%u bytes)", (unsigned)s.outbox[idx].len);
            kp_free(s.outbox[idx].data);
            s.outbox[idx].data = NULL;
            if (victim_off == 0) {
                s.out_head = (s.out_head + 1) % depth;
            }
            else {
                // Close the gap behind the in-flight head.
                for (size_t i = victim_off; i + 1 < s.out_count; i++) {
                    s.outbox[(s.out_head + i) % depth] = s.outbox[(s.out_head + i + 1) % depth];
                }
            }
            s.out_count--;
        }
    }
    if (ok) {
        const size_t idx = (s.out_head + s.out_count) % depth;
        s.outbox[idx].data = data;
        s.outbox[idx].len = len;
        s.outbox[idx].binary = binary;
        s.out_count++;
    }
    kp_mutex_give(s.out_mutex);
    return ok;
}

// Copy the head entry out and mark it in flight. False if empty.
static bool outbox_peek(queued_msg_t* out) {
    if (!kp_mutex_take(s.out_mutex, 1000)) return false;
    bool ok = false;
    if (s.out_count > 0) {
        *out = s.outbox[s.out_head];
        s.out_inflight = true;
        ok = true;
    }
    kp_mutex_give(s.out_mutex);
    return ok;
}

// Remove the in-flight head (the caller owns/frees its data). Returns the
// number of entries still queued.
static size_t outbox_pop_head(void) {
    size_t left = 0;
    if (!kp_mutex_take(s.out_mutex, KP_WAIT_FOREVER)) return 0;
    if (s.out_inflight && s.out_count > 0) {
        s.outbox[s.out_head].data = NULL;
        s.out_head = (s.out_head + 1) % s.cfg.queue_depth;
        s.out_count--;
    }
    s.out_inflight = false;
    left = s.out_count;
    kp_mutex_give(s.out_mutex);
    return left;
}

// Leave the head queued (send failed / offline).
static void outbox_unpeek(void) {
    if (!kp_mutex_take(s.out_mutex, KP_WAIT_FOREVER)) return;
    s.out_inflight = false;
    kp_mutex_give(s.out_mutex);
}

// Wake the sender task. Safe from any task context (timer task, HTTP event
// handlers): it never touches the socket itself.
static void tx_wake(void) {
    if (s.tx_sem) kp_sem_give(s.tx_sem);
}

// Sender task only. peek -> send -> pop: an entry is removed only after its
// write succeeded, so a failed send (link dropped mid-drain) leaves it
// queued for the next wake. Returns true once the outbox is empty.
static bool outbox_flush(void) {
    queued_msg_t msg;
    while (outbox_peek(&msg)) {
        if (!msg.data) {  // defensive: never queued
            outbox_pop_head();
            continue;
        }
        if (!ws_connected_locked_check() || !locked_send(msg.data, msg.len, msg.binary)) {
            outbox_unpeek();
            KP_LOGD(TAG, "Send deferred (%s, %u bytes); left queued",
                msg.binary ? "binary" : "text", (unsigned)msg.len);
            return false;
        }
        outbox_pop_head();
        kp_free(msg.data);
    }
    return true;
}

// deinit only, after the sender task has exited (nothing is in flight).
static void outbox_drain_free(void) {
    if (!s.outbox) return;
    if (!kp_mutex_take(s.out_mutex, KP_WAIT_FOREVER)) return;
    for (size_t i = 0; i < s.out_count; i++) {
        kp_free(s.outbox[(s.out_head + i) % s.cfg.queue_depth].data);
    }
    s.out_head = s.out_count = 0;
    s.out_inflight = false;
    kp_mutex_give(s.out_mutex);
}

// Copy `data` into the outbox and wake the sender. Callers must be inside
// api_enter() or on a cloudlink task.
static bool enqueue_copy(const void* data, size_t len, bool binary) {
    if (!data || len == 0) return false;
    if (len > s.cfg.max_msg_size) {
        KP_LOGW(TAG, "Message of %u bytes exceeds max_msg_size %u",
            (unsigned)len, (unsigned)s.cfg.max_msg_size);
        return false;
    }
    uint8_t* copy = kp_malloc(len);
    if (!copy) {
        KP_LOGE(TAG, "Failed to alloc %u bytes", (unsigned)len);
        return false;
    }
    memcpy(copy, data, len);
    if (!outbox_push(copy, len, binary)) {
        kp_free(copy);  // out_mutex starved or nothing droppable; caller may retry
        return false;
    }
    tx_wake();
    return true;
}

static bool enqueue_text(const char* text) {
    return text ? enqueue_copy(text, strlen(text), false) : false;
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
    if (expires_at > WALL_TIME_SANE_S && now > WALL_TIME_SANE_S && expires_at > now) {
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

// Report the running firmware's identity (and, when configured, the
// hardware SKU) as a twin reported-state patch: fw.{project,version,class}.
// The platform promotes fw.version for rollout bookkeeping and uses fw.class
// to classify unclassified devices for OTA compatibility. Sent on every
// session ready; the server dedups unchanged reports for free.
static void report_fw_identity(void) {
    char project[32] = { 0 };
    char version[32] = { 0 };
    kp_ota_get_app_desc(project, sizeof(project), version, sizeof(version));

    // Class is the silicon target, sourced from the build (never app-supplied)
    // so a device can only ever claim its real chip. Project is the IDF project
    // name; variant is the app-configured build variant. Both become device
    // labels the platform can target OTA deployments on.
    cJSON* root = cJSON_CreateObject();
    if (!root) return;
    cJSON_AddStringToObject(root, "type", "twin.report");
    cJSON_AddStringToObject(root, "mode", "patch");
    cJSON* state = cJSON_AddObjectToObject(root, "state");
    cJSON* fw = state ? cJSON_AddObjectToObject(state, "fw") : NULL;
    if (fw) {
        cJSON_AddStringToObject(fw, "class", CONFIG_IDF_TARGET);
        if (version[0]) cJSON_AddStringToObject(fw, "version", version);
        if (project[0]) cJSON_AddStringToObject(fw, "project", project);
        if (s.cfg.variant && s.cfg.variant[0]) {
            cJSON_AddStringToObject(fw, "variant", s.cfg.variant);
        }
        char* json = cJSON_PrintUnformatted(root);
        if (json) {
            enqueue_text(json);
            cJSON_free(json);
        }
    }
    cJSON_Delete(root);
}

// WS task. The welcome frame proves the whole path works: clear every
// escalation counter, including the reboot-persistent ones.
static void on_session_ready(void) {
    if (!state_lock()) return;
    if (s.session_ready) {
        state_unlock();
        return;
    }
    s.session_ready = true;
    s.sock_failures = 0;
    s.net_resets = 0;
    s.backoff_level = 0;
    s.veto_logged = false;
    s.cap_logged = false;
    state_unlock();

    if (s.welcome_timer) kp_timer_stop(s.welcome_timer);
    if (s.ping_timer) kp_timer_start_periodic(s.ping_timer, PING_INTERVAL_US);
    kp_persist_set(PERSIST_SLOT_NET_RESETS, 0);
    kp_persist_set(PERSIST_SLOT_RESTARTS, 0);

    // Queued behind whatever accumulated while the link was down: the sender
    // task drains strictly in FIFO order, so the app's session-ready burst
    // (enqueued from the callback below) goes out after both.
    report_fw_identity();
    notify_state(KOIOS_CLOUD_STATE_READY);
    if (s.cfg.on_session_ready) s.cfg.on_session_ready();
    koios_ota_on_session_ready();
    tx_wake();
}

static void handle_control_frame(const char* data, size_t len) {
    if (!data || len == 0) {
        KP_LOGW(TAG, "Empty control frame");
        return;
    }

    if (len == 4 && strncmp(data, "pong", 4) == 0) {
        return;
    }

    cJSON* root = cJSON_ParseWithLength(data, len);
    if (!root) {
        KP_LOGW(TAG, "Unparseable control frame (%u bytes)", (unsigned)len);
        for (size_t i = 0; i < len; i++) {
            KP_LOGW(TAG, " %02X", (unsigned char)data[i]);
        }
        KP_LOGW(TAG, "End of unparseable control frame");
        cJSON_Delete(root);
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
            const char* dev_id = cJSON_GetStringValue(cJSON_GetObjectItem(root, "device_id"));
            if (dev_id && dev_id[0] && s.token_mutex && kp_mutex_take(s.token_mutex, 1000)) {
                snprintf(s.device_id, sizeof(s.device_id), "%s", dev_id);
                kp_mutex_give(s.token_mutex);
            }

            const char* issued = cJSON_GetStringValue(cJSON_GetObjectItem(root, "api_key"));
            if (issued && issued[0]) {
                // Server minted a device key (API-key autocreate). Adopt it
                // for future attempts and let the app persist it. The swap
                // runs on the WS event task while start_client() (ctl task)
                // reads s.api_key — guard both with token_mutex or a
                // reconnect racing a welcome frame reads freed memory.
                char* copy = kp_malloc(strlen(issued) + 1);
                if (copy) {
                    strcpy(copy, issued);
                    if (s.token_mutex && kp_mutex_take(s.token_mutex, 1000)) {
                        kp_free(s.api_key);
                        s.api_key = copy;
                        kp_mutex_give(s.token_mutex);
                    }
                    else {
                        kp_free(copy);
                    }
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
            enqueue_text(ack);
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
    else if (strcmp(type, "cert.renew_required") == 0) {
        if (s.cfg.auth_mode != KOIOS_CLOUD_AUTH_MTLS || !s.cfg.on_cert_renew_csr) {
            KP_LOGW(TAG, "cert.renew_required ignored (no handler or not mTLS)");
        }
        else {
            KP_LOGI(TAG, "Server requested certificate renewal");
            char* csr = s.cfg.on_cert_renew_csr();
            if (csr) {
                cJSON* req = cJSON_CreateObject();
                if (req) {
                    cJSON_AddStringToObject(req, "type", "cert.renew_request");
                    cJSON_AddStringToObject(req, "csr", csr);
                    char* json = cJSON_PrintUnformatted(req);
                    if (json) {
                        enqueue_text(json);
                        cJSON_free(json);
                        KP_LOGI(TAG, "Cert renewal CSR sent to server");
                    }
                    cJSON_Delete(req);
                }
                kp_free(csr);
            }
        }
    }
    else if (strcmp(type, "cert.renew_response") == 0) {
        cJSON* ok = cJSON_GetObjectItem(root, "success");
        if (!cJSON_IsTrue(ok)) {
            const char* err = cJSON_GetStringValue(cJSON_GetObjectItem(root, "error"));
            KP_LOGE(TAG, "Cert renewal rejected: %s", err ? err : "unknown");
        }
        else {
            const char* cert = cJSON_GetStringValue(cJSON_GetObjectItem(root, "cert_pem"));
            const char* chain = cJSON_GetStringValue(cJSON_GetObjectItem(root, "chain_pem"));
            if (!cert) {
                KP_LOGE(TAG, "cert.renew_response missing cert_pem");
            }
            else if (s.cfg.on_cert_renewed) {
                s.cfg.on_cert_renewed(cert, chain);
                KP_LOGI(TAG, "Certificate renewed; reconnecting with fresh material");
                if (state_lock()) {
                    s.cert_refresh_requested = true;
                    state_unlock();
                }
                if (s.ctl_sem) kp_sem_give(s.ctl_sem);
            }
        }
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

// WAITING_GATE -> READY once identity / app gate allow it. Evaluates the
// gate (app code) outside the lock.
static void try_advance_state(void) {
    const bool ready = gate_ready();
    bool advanced = false;
    if (!state_lock()) return;
    if (s.state == STATE_WAITING_GATE && ready) {
        s.state = STATE_READY;
        advanced = true;
    }
    state_unlock();
    if (advanced) {
        if (s.gate_timer) kp_timer_stop(s.gate_timer);
        notify_state(KOIOS_CLOUD_STATE_CONNECTING);
        schedule_reconnect();
    }
}

// WS task. Counts the failure, schedules the next attempt, and hands any
// escalation to the control task — never bounces the network or restarts
// from the transport task.
static void handle_ws_disconnect(const kp_ws_disconnect_info_t* info) {
    if (s.welcome_timer) kp_timer_stop(s.welcome_timer);
    if (s.ping_timer) kp_timer_stop(s.ping_timer);

    if (!state_lock()) return;
    if (s.state == STATE_WAITING_NETWORK || s.disconnect_handled) {
        state_unlock();
        return;
    }
    s.disconnect_handled = true;

    const bool was_ready = (s.state == STATE_CONNECTED) && s.session_ready;
    s.state = STATE_READY;
    s.session_ready = false;
    s.backoff_level++;

    bool escalate = false;
    const bool server_answered = info && info->fail_class == KP_WS_FAIL_SERVER;
    if (server_answered) {
        // The peer talked to us (HTTP status, TLS alert, cert rejection,
        // close frame): the local link demonstrably works. Keep backing
        // off, but this is not a reason to bounce WiFi or reboot.
        s.sock_failures = 0;
        KP_LOGW(TAG, "Server rejected/closed the connection (handshake=%d tls=0x%x); "
            "link OK, backing off (level %d)",
            info->handshake_status,
            (unsigned)(info->tls_err < 0 ? -info->tls_err : info->tls_err),
            s.backoff_level);
    }
    else {
        s.sock_failures++;
        KP_LOGW(TAG, "Link failure %d/%d (%s, errno=%d; net resets: %d/%d)",
            s.sock_failures, MAX_SOCK_FAILURES_BEFORE_NET_RESET,
            info ? (info->fail_class == KP_WS_FAIL_LINK ? "no answer" : "unclassified") : "no diagnostics",
            info ? info->sock_errno : 0,
            s.net_resets, MAX_NET_RESETS_BEFORE_RESTART);
        if (s.sock_failures >= MAX_SOCK_FAILURES_BEFORE_NET_RESET) {
            s.sock_failures = 0;
            s.escalate_requested = true;
            escalate = true;
        }
    }
    state_unlock();

    if (was_ready) {
        if (s.cfg.on_disconnect) s.cfg.on_disconnect();
        notify_state(KOIOS_CLOUD_STATE_CONNECTING);
    }
    schedule_reconnect();
    if (escalate && s.ctl_sem) kp_sem_give(s.ctl_sem);
}

static void ws_event(void* arg, kp_ws_event_type_t ev, const uint8_t* data, size_t len) {
    (void)arg;
    switch (ev) {
    case KP_WS_EV_CONNECTED:
        if (state_lock()) {
            s.state = STATE_CONNECTED;
            s.session_ready = false;
            // The local link demonstrably works; only count failures that
            // happen without ever reaching the server.
            s.sock_failures = 0;
            state_unlock();
        }
        if (s.welcome_timer) {
            kp_timer_stop(s.welcome_timer);
            kp_timer_start_once(s.welcome_timer, WELCOME_TIMEOUT_US);
        }
        break;

    case KP_WS_EV_DISCONNECTED:
        handle_ws_disconnect((data && len == sizeof(kp_ws_disconnect_info_t))
            ? (const kp_ws_disconnect_info_t*)data : NULL);
        break;

    case KP_WS_EV_MSG_TEXT:
        handle_control_frame((const char*)data, len);
        break;

    case KP_WS_EV_MSG_BINARY:
        if (s.cfg.on_message) s.cfg.on_message(data, len);
        tx_wake();
        break;
    }
}

// Control task only.
static int start_client(void) {
    if (s.ws) {
        KP_LOGW(TAG, "Client already exists, destroying first");
        // Never open a second client over a live one: the old client's
        // event task would keep dispatching into shared state with no
        // handle left to stop it. (A detached one is fine: its events
        // are masked at the port.)
        if (destroy_ws() == WS_BUSY) return -1;
    }
    if (state_lock()) {
        s.disconnect_handled = false;
        state_unlock();
    }

    kp_ws_config_t cfg = { 0 };
    cfg.url = s.cfg.url;
    cfg.max_rx_size = s.cfg.max_msg_size;
    cfg.on_event = ws_event;
    cfg.event_arg = NULL;

    char* bearer_copy = NULL;
    if (s.cfg.auth_mode == KOIOS_CLOUD_AUTH_MTLS) {
        // Both are fetched once and cached for the process lifetime
        // (released in deinit). Cert first: it is the one that can fail
        // transiently, and a failed attempt must not leave a key context
        // behind (1.3 KB per attempt) or re-fetch one over a cached one.
        if (!s.cert_pem) {
            if (kp_identity_get_client_cert(&s.cert_pem, &s.cert_len) != 0) {
                KP_LOGE(TAG, "Failed to get device certificate");
                s.cert_pem = NULL;
                return -1;
            }
        }
        if (!s.key_ctx) {
            s.key_ctx = kp_identity_get_key_ctx();
            if (!s.key_ctx) {
                KP_LOGE(TAG, "Failed to get identity key context");
                return -1;
            }
        }
        cfg.client_cert_pem = s.cert_pem;
        cfg.client_cert_len = s.cert_len + 1;  // include NUL for PEM parsing
        cfg.client_key_ctx = s.key_ctx;
    }
    else {
        // Snapshot the key under token_mutex: handle_control_frame (WS
        // event task) can free/replace s.api_key while kp_ws_open reads it.
        // kp_ws_open copies the bearer into its own header buffer, so the
        // copy only needs to live across the call.
        if (s.token_mutex && kp_mutex_take(s.token_mutex, 1000)) {
            if (s.api_key) {
                bearer_copy = kp_malloc(strlen(s.api_key) + 1);
                if (bearer_copy) strcpy(bearer_copy, s.api_key);
            }
            kp_mutex_give(s.token_mutex);
        }
        cfg.bearer = bearer_copy;
    }

    kp_ws_t ws = kp_ws_open(&cfg);
    kp_free(bearer_copy);
    if (!ws) return -1;

    if (!s.ws_mutex || !kp_mutex_take(s.ws_mutex, 6000)) {
        kp_ws_close_bounded(ws, WS_CLOSE_TIMEOUT_MS);
        return -1;
    }
    s.ws = ws;
    kp_mutex_give(s.ws_mutex);
    return 0;
}

//------------------------------------------------------------------------------
// Failure cascade (control task only)
//------------------------------------------------------------------------------

// Consults the app's restart policy. Logs the veto once per streak.
static bool escalation_allowed(const char* what) {
    if (!s_may_restart || s_may_restart(s_may_restart_ctx)) return true;
    if (!s.veto_logged) {
        KP_LOGW(TAG, "%s vetoed by the app's restart policy; keeping backoff", what);
        s.veto_logged = true;
    }
    return false;
}

// Returns only if the device is NOT restarting (cap reached or vetoed).
static void try_restart(int net_resets) {
    uint32_t restarts = kp_persist_get(PERSIST_SLOT_RESTARTS);
    const uint32_t last_s = kp_persist_get(PERSIST_SLOT_LAST_RESTART_S);
    const int64_t now_s = kp_wall_time_s();

    // A restart series only counts while its members are close together;
    // once more than the window has passed since the last one (clock
    // permitting), start counting afresh.
    if (restarts > 0 && last_s > (uint32_t)WALL_TIME_SANE_S && now_s > WALL_TIME_SANE_S &&
        now_s - (int64_t)last_s > RESTART_SERIES_WINDOW_S) {
        restarts = 0;
    }

    if (restarts >= MAX_CLOUD_RESTARTS) {
        if (!s.cap_logged) {
            KP_LOGE(TAG, "Restart cap reached (%u restarts without a session); "
                "not restarting again, keeping backoff", (unsigned)restarts);
            s.cap_logged = true;
        }
        return;
    }
    if (!escalation_allowed("Device restart")) return;

    KP_LOGE(TAG, "Too many network resets (%d), restarting (%u/%d)",
        net_resets, (unsigned)restarts + 1, MAX_CLOUD_RESTARTS);
    kp_persist_set(PERSIST_SLOT_RESTARTS, restarts + 1);
    kp_persist_set(PERSIST_SLOT_LAST_RESTART_S,
        now_s > WALL_TIME_SANE_S ? (uint32_t)now_s : 0);
    kp_delay_ms(100);  // let the log line drain
    kp_system_restart();
}

static void run_escalation(void) {
    int net_resets;
    if (!state_lock()) return;
    s.net_resets++;
    net_resets = s.net_resets;
    state_unlock();
    kp_persist_set(PERSIST_SLOT_NET_RESETS, (uint32_t)net_resets);

    if (net_resets >= MAX_NET_RESETS_BEFORE_RESTART) {
        try_restart(net_resets);  // does not return when it restarts
        // Capped or vetoed: fall through to another network bounce.
    }

    KP_LOGW(TAG, "Too many link failures, resetting network (%d/%d)",
        net_resets, MAX_NET_RESETS_BEFORE_RESTART);
    if (!escalation_allowed("Network reset")) return;
    kp_net_reset();
}

//------------------------------------------------------------------------------
// Tasks
//------------------------------------------------------------------------------

// Sender task: the ONLY place frames are written. koios_cloudlink_send used
// to flush inline, which put a blocking mbedTLS record write (up to 11 s
// with the mutex wait) on whatever task called it - the esp_timer task for
// state broadcasts, HTTP event handlers for download progress. Now senders
// (binary and text alike, including the token refresh) just enqueue and
// wake this task. While something is left queued it re-polls every second
// so a deferred entry never has to wait for the next external wake.
static void tx_task(void* arg) {
    (void)arg;
    bool drained = true;
    for (;;) {
        kp_sem_take(s.tx_sem, drained ? KP_WAIT_FOREVER : 1000);
        if (!s.initialized) break;
        drained = outbox_flush();
    }
    s_tx_task_exited = true;  // deinit() waits on this
}

// Control task: single place where clients are torn down and recreated and
// where the failure cascade (network reset / restart) runs.
static void ctl_task(void* arg) {
    (void)arg;
    for (;;) {
        if (!kp_sem_take(s.ctl_sem, KP_WAIT_FOREVER)) continue;
        if (!s.initialized) break;

        bool escalate = false, connect = false;
        if (state_lock()) {
            escalate = s.escalate_requested;
            connect = s.connect_requested;
            s.escalate_requested = false;
            s.connect_requested = false;
            state_unlock();
        }

        if (escalate) run_escalation();

        // Cert renewal: the WS task stored a new cert via the app callback
        // and asked us to reconnect with it. Clear the cached PEM so
        // start_client() re-fetches it from kp_identity, then tear down
        // the live session and reconnect immediately.
        bool cert_refresh = false;
        if (state_lock()) {
            cert_refresh = s.cert_refresh_requested;
            if (cert_refresh) s.cert_refresh_requested = false;
            state_unlock();
        }
        if (cert_refresh) {
            kp_free(s.cert_pem);
            s.cert_pem = NULL;
            KP_LOGI(TAG, "Cert cache cleared for renewal; tearing down for reconnect");
            destroy_ws();
            if (state_lock()) {
                s.backoff_level = 0;
                state_unlock();
            }
            schedule_reconnect();
            continue;
        }

        if (!connect) continue;

        const destroy_result_t gone = destroy_ws();
        bool ready = false;
        if (state_lock()) {
            ready = (s.state == STATE_READY);
            state_unlock();
        }
        if (ready) {
            if (gone == WS_BUSY || start_client() != 0) {
                bump_backoff();
                schedule_reconnect();
            }
        }
    }
    s_ctl_task_exited = true;  // deinit() waits on this
}

//------------------------------------------------------------------------------
// Timer / net callbacks
//------------------------------------------------------------------------------

static void reconnect_timer_cb(void* arg) {
    (void)arg;
    if (state_lock()) {
        s.connect_requested = true;
        state_unlock();
    }
    if (s.ctl_sem) kp_sem_give(s.ctl_sem);
}

static void gate_timer_cb(void* arg) {
    (void)arg;
    bool waiting = false;
    if (state_lock()) {
        waiting = (s.state == STATE_WAITING_GATE);
        state_unlock();
    }
    if (waiting) {
        try_advance_state();
    }
    else if (s.gate_timer) {
        kp_timer_stop(s.gate_timer);
    }
}

static void welcome_timeout_cb(void* arg) {
    (void)arg;
    bool act = false;
    if (state_lock()) {
        if (s.state == STATE_CONNECTED && !s.session_ready) {
            s.disconnect_handled = true;
            s.state = STATE_READY;
            s.backoff_level++;
            act = true;
        }
        state_unlock();
    }
    if (act) {
        KP_LOGW(TAG, "No welcome frame within %llds, reconnecting",
            (long long)(WELCOME_TIMEOUT_US / 1000000));
        notify_state(KOIOS_CLOUD_STATE_CONNECTING);
        schedule_reconnect();
    }
}

static void token_timer_cb(void* arg) {
    (void)arg;
    // Only enqueues (and wakes the sender); never touches the socket. Re-arm
    // a retry in case no token arrives; store_token() replaces it with the
    // real deadline when one does, and a reconnect's welcome frame does too.
    koios_cloudlink_request_token_refresh();
    if (s.token_timer) kp_timer_start_once(s.token_timer, TOKEN_REFRESH_RETRY_US);
}

static void ping_timer_cb(void* arg) {
    (void)arg;
    enqueue_text("ping");
}

static void net_on_connect(void) {
    bool start_gate = false;
    if (state_lock()) {
        if (s.state == STATE_WAITING_NETWORK) {
            s.state = STATE_WAITING_GATE;
            start_gate = true;
        }
        state_unlock();
    }
    if (start_gate) {
        if (s.gate_timer) kp_timer_start_periodic(s.gate_timer, 1000 * 1000);
        try_advance_state();
    }
}

static void net_on_disconnect(void) {
    bool changed = false, was_ready = false;
    if (state_lock()) {
        if (s.state != STATE_WAITING_NETWORK) {
            was_ready = (s.state == STATE_CONNECTED) && s.session_ready;
            s.state = STATE_WAITING_NETWORK;
            s.session_ready = false;
            changed = true;
        }
        state_unlock();
    }
    if (!changed) return;
    if (s.welcome_timer) kp_timer_stop(s.welcome_timer);
    if (s.ping_timer) kp_timer_stop(s.ping_timer);
    // The socket's own DISCONNECTED is ignored in WAITING_NETWORK, so the
    // session-lost notification has to come from here.
    if (was_ready && s.cfg.on_disconnect) s.cfg.on_disconnect();
    notify_state(KOIOS_CLOUD_STATE_WAITING);
}

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

// Release everything init() allocates. Only valid once no task or callback
// can still touch `s` (tasks joined, WS client destroyed, timers stopped).
static void free_primitives(void) {
    kp_timer_t timers[] = { s.token_timer, s.welcome_timer, s.reconnect_timer, s.gate_timer, s.ping_timer };
    for (size_t i = 0; i < sizeof(timers) / sizeof(timers[0]); i++) {
        if (timers[i]) kp_timer_delete(timers[i]);
    }
    s.token_timer = s.welcome_timer = s.reconnect_timer = s.gate_timer = s.ping_timer = NULL;

    if (s.cert_pem) { kp_free(s.cert_pem); s.cert_pem = NULL; }
    if (s.key_ctx) { kp_identity_release_key_ctx(s.key_ctx); s.key_ctx = NULL; }

    kp_free(s.token);
    s.token = NULL;
    kp_free(s.api_key);
    s.api_key = NULL;
    kp_free(s.outbox);
    s.outbox = NULL;

    if (s.ctl_sem) { kp_sem_delete(s.ctl_sem); s.ctl_sem = NULL; }
    if (s.tx_sem) { kp_sem_delete(s.tx_sem); s.tx_sem = NULL; }
    if (s.token_mutex) { kp_mutex_delete(s.token_mutex); s.token_mutex = NULL; }
    if (s.out_mutex) { kp_mutex_delete(s.out_mutex); s.out_mutex = NULL; }
    if (s.ws_mutex) { kp_mutex_delete(s.ws_mutex); s.ws_mutex = NULL; }
    if (s.state_mutex) { kp_mutex_delete(s.state_mutex); s.state_mutex = NULL; }
}

void koios_cloudlink_init(const koios_cloudlink_config_t* config) {
    if (s.initialized || !config || !config->url || !config->on_message) {
        KP_LOGE(TAG, "Invalid init");
        return;
    }
    if (atomic_load(&s_ws_orphaned)) {
        KP_LOGE(TAG, "Orphaned websocket client still live, refusing re-init");
        return;
    }
    if (!s_ctl_task_exited || !s_tx_task_exited || atomic_load(&s_api_users) > 0) {
        // A previous deinit() timed out with the control task or an API
        // caller still inside the state block. memset'ing s under them (or
        // spawning a second control task) would corrupt state. Once the
        // stragglers exit, re-init becomes possible again. New API callers
        // can't sneak in here: s_teardown stays set until init() succeeds.
        KP_LOGE(TAG, "Previous cloudlink users still active, refusing re-init");
        return;
    }

    memset(&s, 0, sizeof(s));
    s.cfg = *config;
    if (s.cfg.max_msg_size == 0) s.cfg.max_msg_size = DEFAULT_MAX_MSG_SIZE;
    if (s.cfg.queue_depth == 0) s.cfg.queue_depth = DEFAULT_QUEUE_DEPTH;

    if (config->api_key) {
        s.api_key = kp_malloc(strlen(config->api_key) + 1);
        if (!s.api_key) {
            KP_LOGE(TAG, "Failed to copy api key");
            return;
        }
        strcpy(s.api_key, config->api_key);
    }

    s.state_mutex = kp_mutex_create();
    s.ws_mutex = kp_mutex_create();
    s.out_mutex = kp_mutex_create();
    s.token_mutex = kp_mutex_create();
    s.ctl_sem = kp_sem_create();
    s.tx_sem = kp_sem_create();
    s.outbox = kp_calloc(s.cfg.queue_depth, sizeof(queued_msg_t));
    s.reconnect_timer = kp_timer_create("cl_reconn", reconnect_timer_cb, NULL);
    s.gate_timer = kp_timer_create("cl_gate", gate_timer_cb, NULL);
    s.welcome_timer = kp_timer_create("cl_welcome", welcome_timeout_cb, NULL);
    s.token_timer = kp_timer_create("cl_token", token_timer_cb, NULL);
    s.ping_timer = kp_timer_create("cl_ping", ping_timer_cb, NULL);

    if (!s.state_mutex || !s.ws_mutex || !s.out_mutex || !s.token_mutex ||
        !s.ctl_sem || !s.tx_sem || !s.outbox ||
        !s.reconnect_timer || !s.gate_timer || !s.welcome_timer || !s.token_timer ||
        !s.ping_timer) {
        KP_LOGE(TAG, "Failed to allocate primitives");
        free_primitives();
        return;
    }

    // Resume the failure cascade where the previous boot left it: a restart
    // must not hand out a fresh multi-hour escalation budget.
    s.net_resets = (int)kp_persist_get(PERSIST_SLOT_NET_RESETS);
    {
        const uint32_t restarts = kp_persist_get(PERSIST_SLOT_RESTARTS);
        if (s.net_resets || restarts) {
            KP_LOGW(TAG, "Resuming failure cascade: %d net resets, %u restarts since last session",
                s.net_resets, (unsigned)restarts);
        }
    }

    s.state = STATE_WAITING_NETWORK;
    s.initialized = true;

    s_ctl_task_exited = false;
    if (!kp_task_spawn("cloudlink_ctl", ctl_task, NULL, 4096, 10)) {
        KP_LOGE(TAG, "Failed to spawn control task");
        s.initialized = false;
        s_ctl_task_exited = true;  // nothing spawned; allow a retry
        free_primitives();
        return;
    }
    // 6 KB: this task runs the TLS record write for every outbound frame.
    s_tx_task_exited = false;
    if (!kp_task_spawn("cloudlink_tx", tx_task, NULL, 6144, 9)) {
        KP_LOGE(TAG, "Failed to spawn sender task");
        s.initialized = false;
        s_tx_task_exited = true;
        // The control task is idle on ctl_sem: wake it so it observes
        // !initialized and exits, then reclaim everything.
        kp_sem_give(s.ctl_sem);
        for (int waited = 0; !s_ctl_task_exited && waited < 2000; waited += 10) kp_delay_ms(10);
        if (!s_ctl_task_exited) {
            KP_LOGE(TAG, "Control task did not exit - leaking cloudlink state");
            return;
        }
        free_primitives();
        return;
    }

    // Everything senders touch is live; reopen the public API.
    atomic_store(&s_teardown, false);

    KP_LOGI(TAG, "Outbox: %u slots x %u B max (worst case %u KiB, allocated on demand)",
        (unsigned)s.cfg.queue_depth, (unsigned)s.cfg.max_msg_size,
        (unsigned)((s.cfg.queue_depth * s.cfg.max_msg_size + 1023) / 1024));

    kp_net_subscribe(net_on_connect, net_on_disconnect);

    if (kp_net_is_connected()) {
        net_on_connect();
    }
    else {
        notify_state(KOIOS_CLOUD_STATE_WAITING);
    }
}

void koios_cloudlink_deinit(void) {
    // Close the public API first: entrants now bounce off api_enter(). The
    // exchange also makes concurrent deinit calls single-shot (the old
    // check-then-clear of s.initialized let two callers both tear down).
    if (atomic_exchange(&s_teardown, true)) return;
    if (!s.initialized) return;  // s_teardown stays set; init() reopens it
    s.initialized = false;

    // NOTE teardown order: the WS event task (ws_event → handle_control_frame
    // → store_token → kp_timer_stop/start) and the esp_timer callbacks touch
    // timers and token state ungated — they are quiesced by ORDER, not by the
    // api_enter() gate. Timers must therefore be deleted only after
    // destroy_ws() has joined the WS task, and state freed only after both.

    // Wake the control and sender tasks so they observe !initialized and
    // exit, then JOIN them. A fixed sleep is not enough: the control task
    // can be seconds deep in a TLS handshake inside start_client(), still
    // referencing s.cert_pem / s.key_ctx / s.ws_mutex — freeing those under
    // it is a use-after-free, and re-init afterwards would spawn a second
    // control task over the same state block.
    if (s.ctl_sem) kp_sem_give(s.ctl_sem);
    if (s.tx_sem) kp_sem_give(s.tx_sem);
    int waited_ms = 0;
    const int max_wait_ms = 30000;
    while ((!s_ctl_task_exited || !s_tx_task_exited) && waited_ms < max_wait_ms) {
        kp_delay_ms(50);
        waited_ms += 50;
    }
    if (!s_ctl_task_exited || !s_tx_task_exited) {
        // The task is stuck; tearing down the state it uses would corrupt
        // the heap. Leak everything deliberately and refuse re-init until
        // the task eventually exits (init checks s_ctl_task_exited).
        KP_LOGE(TAG, "Control/sender task did not exit after %dms - leaking cloudlink state", max_wait_ms);
        return;
    }

    // Drain in-flight public API calls (send/is_ready/... from the timer,
    // job, and handler tasks). s_teardown is already set, so no new callers
    // can enter; the ones inside are bounded by their mutex/send timeouts.
    waited_ms = 0;
    while (atomic_load(&s_api_users) > 0 && waited_ms < max_wait_ms) {
        kp_delay_ms(10);
        waited_ms += 10;
    }
    if (atomic_load(&s_api_users) > 0) {
        // Freeing under a live caller is heap corruption; leak instead.
        KP_LOGE(TAG, "API callers did not drain after %dms - leaking cloudlink state", max_wait_ms);
        return;
    }

    // Claim and destroy the WS client BEFORE freeing anything. destroy_ws
    // can be starved of ws_mutex by a sender mid-kp_ws_send (≤5s hold) —
    // retry rather than proceed: freeing state under a live client is
    // exactly the double-free-of-s.token → SPIRAM corruption this ordering
    // exists to prevent.
    destroy_result_t gone = WS_BUSY;
    for (int attempt = 0; attempt < 5 && gone == WS_BUSY; attempt++) {
        gone = destroy_ws();
    }
    if (gone != WS_DESTROYED) {
        // Live or detached client whose task may still be inside a
        // callback that touches this state: leak the entire state block
        // deliberately and refuse re-init for the rest of this boot.
        // Freeing anything here would corrupt the heap.
        atomic_store(&s_ws_orphaned, true);
        KP_LOGE(TAG, "WS client could not be joined - leaking cloudlink state");
        return;
    }

    // WS task joined; nothing can restart timers now. Stop them, give any
    // in-flight esp_timer callback a beat to drain, then delete.
    kp_timer_t timers[] = { s.token_timer, s.welcome_timer, s.reconnect_timer, s.gate_timer, s.ping_timer };
    for (size_t i = 0; i < sizeof(timers) / sizeof(timers[0]); i++) {
        if (timers[i]) kp_timer_stop(timers[i]);
    }
    kp_delay_ms(20);

    outbox_drain_free();
    free_primitives();
}

void koios_cloudlink_set_restart_policy(bool (*may_restart)(void* ctx), void* ctx) {
    s_may_restart_ctx = ctx;
    s_may_restart = may_restart;
}

bool koios_cloudlink_is_connected(void) {
    if (!api_enter()) return false;
    bool connected = ws_connected_locked_check();
    api_exit();
    return connected;
}

bool koios_cloudlink_is_ready(void) {
    if (!api_enter()) return false;
    bool ready = false;
    if (state_lock()) {
        ready = s.session_ready;
        state_unlock();
    }
    if (ready) ready = ws_connected_locked_check();
    api_exit();
    return ready;
}

bool koios_cloudlink_send(const void* data, size_t len) {
    if (!data || len == 0) return false;
    if (!api_enter()) return false;
    bool ok = enqueue_copy(data, len, true);
    api_exit();
    return ok;
}

bool koios_cloudlink_send_text(const char* text) {
    if (!text) return false;
    if (!api_enter()) return false;
    bool ok = enqueue_text(text);
    api_exit();
    return ok;
}

char* koios_cloudlink_get_token_copy(void) {
    if (!api_enter()) return NULL;
    char* copy = NULL;
    if (s.token_mutex && kp_mutex_take(s.token_mutex, 1000)) {
        if (s.token) {
            size_t len = strlen(s.token) + 1;
            copy = kp_malloc(len);
            if (copy) memcpy(copy, s.token, len);
        }
        kp_mutex_give(s.token_mutex);
    }
    api_exit();
    return copy;
}

bool koios_cloudlink_get_device_id(char* out, size_t out_size) {
    if (!out || out_size == 0) return false;
    out[0] = '\0';
    if (!api_enter()) return false;
    bool have_id = false;
    if (s.token_mutex && kp_mutex_take(s.token_mutex, 1000)) {
        if (s.device_id[0]) {
            snprintf(out, out_size, "%s", s.device_id);
            have_id = true;
        }
        kp_mutex_give(s.token_mutex);
    }
    api_exit();
    return have_id;
}

void koios_cloudlink_request_token_refresh(void) {
    if (!api_enter()) return;
    // Only while the session is up: a reconnect delivers a fresh token in
    // the welcome frame anyway, and queueing refreshes while offline would
    // crowd the app's messages out of the outbox.
    bool ready = false;
    if (state_lock()) {
        ready = s.session_ready;
        state_unlock();
    }
    if (!ready) {
        api_exit();
        return;
    }
    int64_t now_us = kp_monotonic_us();
    if (s.last_refresh_req_us > 0 &&
        (now_us - s.last_refresh_req_us) < TOKEN_REFRESH_MIN_INTERVAL_US) {
        api_exit();
        return;
    }
    // Queued like any other frame: the sender task writes it, so this is
    // safe from timer callbacks and HTTP handlers.
    if (enqueue_text("{\"type\":\"token.refresh\"}")) {
        s.last_refresh_req_us = now_us;
    }
    api_exit();
}
