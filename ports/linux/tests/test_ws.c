// The WebSocket client against a scripted server in this process: framing in
// both directions (all three length forms, fragments, a control frame between
// fragments, bytes arriving one at a time), the size bound, and how every way
// of losing the connection is classified.

#include "check.h"

#include "koios/linux.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_websocket.h"

#include <openssl/evp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

//------------------------------------------------------------------------------
// What the client reported
//------------------------------------------------------------------------------

#define MAX_EVENTS 32

typedef struct {
    kp_ws_event_type_t type;
    size_t len;
    uint8_t head[16];       // first bytes of a message
    uint32_t sum;           // sum of all its bytes
    kp_ws_disconnect_info_t info;
} event_t;

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static event_t s_events[MAX_EVENTS];
static int s_event_count;
static atomic_int s_block_ms;  // make the callback block (teardown test)

static void on_event(void* arg, kp_ws_event_type_t type, const uint8_t* data, size_t len) {
    (void)arg;
    pthread_mutex_lock(&s_lock);
    if (s_event_count < MAX_EVENTS) {
        event_t* e = &s_events[s_event_count++];
        memset(e, 0, sizeof(*e));
        e->type = type;
        e->len = len;
        if (type == KP_WS_EV_DISCONNECTED) {
            if (data && len == sizeof(e->info)) memcpy(&e->info, data, sizeof(e->info));
        }
        else if (data) {
            memcpy(e->head, data, len < sizeof(e->head) ? len : sizeof(e->head));
            for (size_t i = 0; i < len; i++) e->sum += data[i];
        }
    }
    pthread_mutex_unlock(&s_lock);
    const int block = atomic_load(&s_block_ms);
    if (block && type == KP_WS_EV_MSG_TEXT) kp_delay_ms((uint32_t)block);
}

static int event_count(void) {
    pthread_mutex_lock(&s_lock);
    const int n = s_event_count;
    pthread_mutex_unlock(&s_lock);
    return n;
}

static void events_reset(void) {
    pthread_mutex_lock(&s_lock);
    s_event_count = 0;
    pthread_mutex_unlock(&s_lock);
}

static bool wait_events(int n, int timeout_ms) {
    for (int waited = 0; waited < timeout_ms; waited += 10) {
        if (event_count() >= n) return true;
        kp_delay_ms(10);
    }
    return event_count() >= n;
}

static bool last_is_disconnect(event_t* out) {
    pthread_mutex_lock(&s_lock);
    const bool ok = s_event_count > 0 && s_events[s_event_count - 1].type == KP_WS_EV_DISCONNECTED;
    if (ok) *out = s_events[s_event_count - 1];
    pthread_mutex_unlock(&s_lock);
    return ok;
}

//------------------------------------------------------------------------------
// The scripted server
//------------------------------------------------------------------------------

typedef enum { SCN_BASIC, SCN_HTTP_403, SCN_DROP, SCN_IDLE } scenario_t;

static struct {
    int listen_fd;
    int port;
    scenario_t scenario;
    pthread_t thread;
    atomic_bool saw_bearer;
    atomic_int client_frames_ok;
    atomic_bool pong_ok;
    atomic_bool close_echoed;
} srv;

static void send_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = buf;
    while (len > 0) {
        const ssize_t n = send(fd, p, len, 0);
        if (n <= 0) return;
        p += n;
        len -= (size_t)n;
    }
}

static bool recv_all(int fd, void* buf, size_t len) {
    uint8_t* p = buf;
    while (len > 0) {
        const ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) return false;
        p += n;
        len -= (size_t)n;
    }
    return true;
}

// An unmasked server frame. slow: one byte per segment, to make the client's
// parser see every possible split.
static void send_frame(int fd, bool fin, uint8_t opcode, const void* data, size_t len, bool slow) {
    uint8_t hdr[10];
    size_t n = 0;
    hdr[n++] = (uint8_t)((fin ? 0x80 : 0) | opcode);
    if (len < 126) hdr[n++] = (uint8_t)len;
    else if (len <= 0xFFFF) { hdr[n++] = 126; hdr[n++] = (uint8_t)(len >> 8); hdr[n++] = (uint8_t)len; }
    else { hdr[n++] = 127; for (int i = 7; i >= 0; i--) hdr[n++] = (uint8_t)((uint64_t)len >> (8 * i)); }
    if (slow) {
        for (size_t i = 0; i < n; i++) { send_all(fd, hdr + i, 1); usleep(1500); }
        for (size_t i = 0; i < len; i++) { send_all(fd, (const uint8_t*)data + i, 1); usleep(1500); }
    }
    else {
        send_all(fd, hdr, n);
        send_all(fd, data, len);
    }
}

// Read one client frame (must be masked); returns its opcode and the
// unmasked payload (malloc'd), or -1.
static int read_frame(int fd, uint8_t** payload, size_t* len) {
    uint8_t h[2];
    if (!recv_all(fd, h, 2)) return -1;
    if (!(h[1] & 0x80)) return -1;  // a client must mask
    uint64_t n = h[1] & 0x7F;
    if (n == 126) {
        uint8_t e[2];
        if (!recv_all(fd, e, 2)) return -1;
        n = (uint64_t)e[0] << 8 | e[1];
    }
    else if (n == 127) {
        uint8_t e[8];
        if (!recv_all(fd, e, 8)) return -1;
        n = 0;
        for (int i = 0; i < 8; i++) n = n << 8 | e[i];
    }
    uint8_t mask[4];
    if (!recv_all(fd, mask, 4)) return -1;
    uint8_t* buf = malloc(n + 1);
    if (!buf || !recv_all(fd, buf, n)) { free(buf); return -1; }
    for (uint64_t i = 0; i < n; i++) buf[i] ^= mask[i & 3];
    buf[n] = '\0';
    *payload = buf;
    *len = (size_t)n;
    return h[0] & 0x0F;
}

static uint8_t* pattern(size_t len, uint32_t* sum) {
    uint8_t* buf = malloc(len);
    uint32_t s = 0;
    for (size_t i = 0; i < len; i++) { buf[i] = (uint8_t)(i * 31 + 7); s += buf[i]; }
    if (sum) *sum = s;
    return buf;
}

static void* server_thread(void* arg) {
    (void)arg;
    const int fd = accept(srv.listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // The request head.
    char req[4096];
    size_t got = 0;
    while (got < sizeof(req) - 1) {
        const ssize_t n = recv(fd, req + got, sizeof(req) - 1 - got, 0);
        if (n <= 0) { close(fd); return NULL; }
        got += (size_t)n;
        req[got] = '\0';
        if (strstr(req, "\r\n\r\n")) break;
    }
    atomic_store(&srv.saw_bearer, strstr(req, "Authorization: Bearer test-key\r\n") != NULL);

    if (srv.scenario == SCN_HTTP_403) {
        const char* resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        send_all(fd, resp, strlen(resp));
        usleep(100000);
        close(fd);
        return NULL;
    }

    const char* key = strcasestr(req, "Sec-WebSocket-Key:");
    char keyval[64] = "";
    if (key) sscanf(key + 18, " %63[^\r\n]", keyval);
    char concat[128], accept_b64[64];
    unsigned char sha[EVP_MAX_MD_SIZE];
    unsigned int sha_len = 0;
    snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", keyval);
    EVP_Digest(concat, strlen(concat), sha, &sha_len, EVP_sha1(), NULL);
    EVP_EncodeBlock((unsigned char*)accept_b64, sha, (int)sha_len);
    char resp[256];
    snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept_b64);

    if (srv.scenario == SCN_DROP) {
        send_all(fd, resp, strlen(resp));
        usleep(150000);
        close(fd);  // gone without a close frame
        return NULL;
    }
    if (srv.scenario == SCN_IDLE) {
        send_all(fd, resp, strlen(resp));
        send_frame(fd, true, 0x1, "hi", 2, false);
        char sink[256];
        while (recv(fd, sink, sizeof(sink), 0) > 0) {}
        close(fd);
        return NULL;
    }

    // SCN_BASIC. The first frame rides in the same segment as the response
    // head: the client must not lose bytes that follow the handshake.
    char first[300];
    const size_t rl = strlen(resp);
    memcpy(first, resp, rl);
    first[rl] = (char)0x81;
    first[rl + 1] = 5;
    memcpy(first + rl + 2, "hello", 5);
    send_all(fd, first, rl + 7);

    // A binary message in three fragments with a ping in the middle.
    send_frame(fd, false, 0x2, "ab", 2, true);
    send_frame(fd, true, 0x9, "p1", 2, true);
    send_frame(fd, false, 0x0, "cd", 2, true);
    send_frame(fd, true, 0x0, "ef", 2, true);
    uint8_t* payload;
    size_t len;
    int op = read_frame(fd, &payload, &len);
    atomic_store(&srv.pong_ok, op == 0xA && len == 2 && memcmp(payload, "p1", 2) == 0);
    if (op >= 0) free(payload);

    // 16-bit and 64-bit lengths.
    uint8_t* mid = pattern(300, NULL);
    send_frame(fd, true, 0x2, mid, 300, false);
    free(mid);
    uint8_t* big = pattern(70000, NULL);
    send_frame(fd, true, 0x2, big, 70000, false);
    free(big);
    // Over the client's bound: dropped there, and the stream stays in step.
    uint8_t* huge = pattern(200000, NULL);
    send_frame(fd, true, 0x2, huge, 200000, false);
    free(huge);
    send_frame(fd, true, 0x1, "after", 5, false);

    // What the client sends: text, 300 bytes, 70000 bytes.
    static const size_t want_len[3] = { 16, 300, 70000 };
    static const int want_op[3] = { 0x1, 0x2, 0x2 };
    for (int i = 0; i < 3; i++) {
        op = read_frame(fd, &payload, &len);
        if (op < 0) break;
        bool ok = op == want_op[i] && len == want_len[i];
        if (ok && i == 0) ok = memcmp(payload, "ping-from-client", 16) == 0;
        if (ok && i > 0) {
            uint8_t* expect = pattern(len, NULL);
            ok = memcmp(payload, expect, len) == 0;
            free(expect);
        }
        if (ok) atomic_fetch_add(&srv.client_frames_ok, 1);
        free(payload);
    }
    send_frame(fd, true, 0x1, "ok", 2, false);

    // Close with a status and a reason; the client echoes the status.
    const uint8_t bye[] = { 0x03, 0xE8, 'b', 'y', 'e' };
    send_frame(fd, true, 0x8, bye, sizeof(bye), false);
    op = read_frame(fd, &payload, &len);
    atomic_store(&srv.close_echoed, op == 0x8 && len == 2 && payload[0] == 0x03 && payload[1] == 0xE8);
    if (op >= 0) free(payload);
    close(fd);
    return NULL;
}

static void server_start(scenario_t scenario) {
    srv.scenario = scenario;
    atomic_store(&srv.saw_bearer, false);
    atomic_store(&srv.client_frames_ok, 0);
    atomic_store(&srv.pong_ok, false);
    atomic_store(&srv.close_echoed, false);
    srv.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv.listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(srv.listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv.listen_fd, 1);
    socklen_t al = sizeof(addr);
    getsockname(srv.listen_fd, (struct sockaddr*)&addr, &al);
    srv.port = ntohs(addr.sin_port);
    pthread_create(&srv.thread, NULL, server_thread, NULL);
}

static void server_join(void) {
    shutdown(srv.listen_fd, SHUT_RDWR);
    close(srv.listen_fd);
    pthread_join(srv.thread, NULL);
}

static kp_ws_t open_client(const char* url_fmt, int port, const char* bearer) {
    char url[128];
    snprintf(url, sizeof(url), url_fmt, port);
    const kp_ws_config_t cfg = {
        .url = url,
        .bearer = bearer,
        .max_rx_size = 100000,
        .on_event = on_event,
    };
    return kp_ws_open(&cfg);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    koios_linux_init(NULL);
    event_t last;

    // ---- Framing, both ways ------------------------------------------------
    server_start(SCN_BASIC);
    events_reset();
    kp_ws_t ws = open_client("ws://127.0.0.1:%d/path?x=1", srv.port, "test-key");
    CHECK(ws != NULL);
    // CONNECTED, "hello", "abcdef", 300 bytes, 70000 bytes, "after"
    CHECK(wait_events(6, 10000));
    CHECK(kp_ws_is_connected(ws));
    CHECK(kp_ws_send(ws, "ping-from-client", 16, false, 2000));
    uint32_t sum300, sum70000;
    uint8_t* p300 = pattern(300, &sum300);
    uint8_t* p70000 = pattern(70000, &sum70000);
    CHECK(kp_ws_send(ws, p300, 300, true, 2000));
    CHECK(kp_ws_send(ws, p70000, 70000, true, 5000));
    // "ok", then the close
    CHECK(wait_events(8, 10000));
    pthread_mutex_lock(&s_lock);
    CHECK_EQ(s_events[0].type, KP_WS_EV_CONNECTED);
    CHECK_EQ(s_events[1].type, KP_WS_EV_MSG_TEXT);
    CHECK_EQ(s_events[1].len, 5);
    CHECK(memcmp(s_events[1].head, "hello", 5) == 0);
    CHECK_EQ(s_events[2].type, KP_WS_EV_MSG_BINARY);   // the fragments, joined
    CHECK_EQ(s_events[2].len, 6);
    CHECK(memcmp(s_events[2].head, "abcdef", 6) == 0);
    CHECK_EQ(s_events[3].len, 300);
    CHECK_EQ(s_events[3].sum, sum300);
    CHECK_EQ(s_events[4].len, 70000);
    CHECK_EQ(s_events[4].sum, sum70000);
    CHECK_EQ(s_events[5].type, KP_WS_EV_MSG_TEXT);     // the 200000-byte one is not here
    CHECK(memcmp(s_events[5].head, "after", 5) == 0);
    CHECK(memcmp(s_events[6].head, "ok", 2) == 0);
    CHECK_EQ(s_events[7].type, KP_WS_EV_DISCONNECTED);
    CHECK_EQ(s_events[7].info.fail_class, KP_WS_FAIL_SERVER);
    CHECK(s_events[7].info.was_connected);
    pthread_mutex_unlock(&s_lock);
    server_join();
    CHECK(atomic_load(&srv.saw_bearer));
    CHECK(atomic_load(&srv.pong_ok));
    CHECK_EQ(atomic_load(&srv.client_frames_ok), 3);
    CHECK(atomic_load(&srv.close_echoed));
    CHECK(!kp_ws_is_connected(ws));
    CHECK(!kp_ws_send(ws, "x", 1, false, 100));  // a dead socket takes nothing
    CHECK(kp_ws_close_bounded(ws, 2000));
    free(p300);
    free(p70000);

    // ---- The server refuses the upgrade: it answered ------------------------
    server_start(SCN_HTTP_403);
    events_reset();
    ws = open_client("ws://127.0.0.1:%d/", srv.port, NULL);
    CHECK(wait_events(1, 5000));
    CHECK(last_is_disconnect(&last));
    CHECK_EQ(last.info.fail_class, KP_WS_FAIL_SERVER);
    CHECK_EQ(last.info.handshake_status, 403);
    CHECK(!last.info.was_connected);
    CHECK_EQ(event_count(), 1);  // exactly one event for the attempt
    kp_ws_close(ws);
    server_join();

    // ---- The peer vanishes after the upgrade ---------------------------------
    server_start(SCN_DROP);
    events_reset();
    ws = open_client("ws://127.0.0.1:%d/", srv.port, NULL);
    CHECK(wait_events(2, 5000));
    CHECK(last_is_disconnect(&last));
    CHECK_EQ(last.info.fail_class, KP_WS_FAIL_SERVER);  // a FIN is an answer
    CHECK(last.info.was_connected);
    kp_ws_close(ws);
    server_join();

    // ---- Nobody listens: the host answered with a reset ----------------------
    events_reset();
    ws = open_client("ws://127.0.0.1:%d/", srv.port, NULL);  // the port just closed
    CHECK(wait_events(1, 5000));
    CHECK(last_is_disconnect(&last));
    CHECK_EQ(last.info.fail_class, KP_WS_FAIL_SERVER);
    CHECK_EQ(last.info.sock_errno, ECONNREFUSED);
    kp_ws_close(ws);

    // ---- No such host: nothing answered --------------------------------------
    events_reset();
    ws = open_client("ws://no-such-host.invalid:%d/", 80, NULL);
    CHECK(wait_events(1, 30000));
    CHECK(last_is_disconnect(&last));
    CHECK_EQ(last.info.fail_class, KP_WS_FAIL_LINK);
    kp_ws_close(ws);

    // ---- A bad URL is refused at open ------------------------------------------
    CHECK(open_client("http://127.0.0.1:%d/", 80, NULL) == NULL);

    // ---- Close while connected: prompt, and silent afterwards ------------------
    server_start(SCN_IDLE);
    events_reset();
    ws = open_client("ws://127.0.0.1:%d/", srv.port, NULL);
    CHECK(wait_events(2, 5000));  // CONNECTED, "hi"
    int64_t t0 = kp_monotonic_us();
    CHECK(kp_ws_close_bounded(ws, 5000));
    CHECK(kp_monotonic_us() - t0 < 1000 * 1000);
    kp_delay_ms(200);
    CHECK_EQ(event_count(), 2);  // no DISCONNECTED after a close
    server_join();

    // ---- A callback that blocks: the close gives up and detaches ----------------
    server_start(SCN_IDLE);
    events_reset();
    atomic_store(&s_block_ms, 1500);
    ws = open_client("ws://127.0.0.1:%d/", srv.port, NULL);
    CHECK(wait_events(2, 5000));
    t0 = kp_monotonic_us();
    CHECK(!kp_ws_close_bounded(ws, 300));  // the thread is inside the callback
    const int64_t took = kp_monotonic_us() - t0;
    CHECK(took >= 250 * 1000 && took < 1200 * 1000);
    atomic_store(&s_block_ms, 0);
    kp_delay_ms(1800);  // the detached thread finishes and frees itself
    CHECK_EQ(event_count(), 2);
    server_join();

    CHECK_DONE();
}
