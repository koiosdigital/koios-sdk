// WebSocket client (RFC 6455) over OpenSSL, one thread per connection.
//
// Written directly on OpenSSL rather than on a WebSocket library for three
// reasons the core's contract brings with it: the client key may live behind
// a provider (PKCS#11), so the TLS stack has to take an EVP_PKEY handle; every
// way a connection can fail has to be told apart (nothing answered / the
// server answered), because only the first kind may escalate; and teardown
// has to be bounded even when an application callback blocks the thread.
//
// ws:// (no TLS) is supported for tests against a local gateway.

#include "koios/port/kp_websocket.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "kp_linux.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static const char* TAG = "kp_ws";

#define CONNECT_TIMEOUT_MS   15000
#define PING_INTERVAL_US     (25LL * 1000 * 1000)
#define RX_TIMEOUT_US        (60LL * 1000 * 1000)
#define IN_BUF_SIZE          (16 * 1024)
#define MAX_HANDSHAKE_BYTES  (8 * 1024)
#define WS_GUID              "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef enum { ST_HEADER, ST_PAYLOAD } parse_state_t;

struct kp_ws {
    // What to connect to
    bool tls;
    char* host;
    char* path;
    int port;
    char* bearer;
    char* protocols;
    X509* cert;
    STACK_OF(X509)* chain;
    EVP_PKEY* pkey;
    size_t max_rx_size;
    kp_ws_event_fn on_event;
    void* event_arg;

    // The connection. io_lock serialises every read and write on ssl/fd: the
    // connection thread reads, any thread may send.
    pthread_mutex_t io_lock;
    int fd;
    SSL_CTX* ctx;
    SSL* ssl;
    int wake_pipe[2];
    atomic_bool connected;
    atomic_bool closing;
    atomic_bool tx_failed;

    // Input buffer and frame parser (connection thread only)
    uint8_t* in_buf;
    size_t in_len;
    parse_state_t state;
    bool cur_fin, cur_masked, cur_control;
    uint8_t cur_opcode;
    uint8_t cur_mask[4];
    uint64_t cur_remaining;
    uint64_t cur_offset;
    uint8_t ctl_buf[125];
    size_t ctl_len;
    bool msg_active, msg_is_text, msg_dropping;
    uint8_t* msg_buf;
    size_t msg_len, msg_cap;
    int64_t last_rx_us, last_ping_us;

    // Lifetime: the opener and the connection thread each hold a reference.
    atomic_int owners;
    pthread_mutex_t done_lock;
    pthread_cond_t done_cond;
    bool done;
};

//------------------------------------------------------------------------------
// Small helpers
//------------------------------------------------------------------------------

static void set_nonblocking(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static kp_ws_fail_class_t classify_errno(int e) {
    switch (e) {
    case ECONNREFUSED:
    case ECONNRESET:
        return KP_WS_FAIL_SERVER;  // TCP answered: the path to the host works
    case 0:
        return KP_WS_FAIL_UNKNOWN;
    default:
        return KP_WS_FAIL_LINK;    // timeouts, unreachable, down, pipe
    }
}

static const char* class_name(kp_ws_fail_class_t c) {
    switch (c) {
    case KP_WS_FAIL_LINK:   return "link";
    case KP_WS_FAIL_SERVER: return "server";
    default:                return "unknown";
    }
}

// Wait for fd to become readable/writable, or for the wake pipe. Returns 1
// when fd is ready, 0 on timeout, -1 when woken for close or on error.
static int wait_fd(struct kp_ws* ws, short events, int timeout_ms) {
    struct pollfd p[2] = {
        { .fd = ws->fd, .events = events },
        { .fd = ws->wake_pipe[0], .events = POLLIN },
    };
    for (;;) {
        const int rc = poll(p, 2, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) return 0;
        if (p[1].revents) return -1;
        return 1;
    }
}

static int ms_left(int64_t deadline_us) {
    const int64_t left = deadline_us - kp_monotonic_us();
    if (left <= 0) return 0;
    return (int)((left + 999) / 1000);
}

//------------------------------------------------------------------------------
// Raw I/O (io_lock held). Both return bytes moved, 0 for "would block" and
// -1 for a dead connection; *want is the poll event that unblocks a 0.
//------------------------------------------------------------------------------

static int io_read(struct kp_ws* ws, void* buf, size_t len, short* want, bool* eof) {
    *want = POLLIN;
    *eof = false;
    if (ws->ssl) {
        ERR_clear_error();
        errno = 0;
        const int n = SSL_read(ws->ssl, buf, (int)len);
        if (n > 0) return n;
        switch (SSL_get_error(ws->ssl, n)) {
        case SSL_ERROR_WANT_READ:  return 0;
        case SSL_ERROR_WANT_WRITE: *want = POLLOUT; return 0;
        case SSL_ERROR_ZERO_RETURN: *eof = true; return -1;
        case SSL_ERROR_SYSCALL: if (errno == 0) *eof = true; return -1;
        default: errno = 0; return -1;  // a TLS-level error, not a socket one
        }
    }
    const ssize_t n = recv(ws->fd, buf, len, 0);
    if (n > 0) return (int)n;
    if (n == 0) { *eof = true; return -1; }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    return -1;
}

static int io_write(struct kp_ws* ws, const void* buf, size_t len, short* want) {
    *want = POLLOUT;
    if (ws->ssl) {
        ERR_clear_error();
        const int n = SSL_write(ws->ssl, buf, (int)len);
        if (n > 0) return n;
        switch (SSL_get_error(ws->ssl, n)) {
        case SSL_ERROR_WANT_WRITE: return 0;
        case SSL_ERROR_WANT_READ:  *want = POLLIN; return 0;
        default: return -1;
        }
    }
    const ssize_t n = send(ws->fd, buf, len, MSG_NOSIGNAL);
    if (n > 0) return (int)n;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return -1;
}

// Write everything or fail (io_lock held).
static bool io_write_all(struct kp_ws* ws, const uint8_t* buf, size_t len, int64_t deadline_us) {
    size_t off = 0;
    while (off < len) {
        short want;
        const int n = io_write(ws, buf + off, len - off, &want);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0) return false;
        const int left = ms_left(deadline_us);
        if (left == 0) return false;
        struct pollfd p = { .fd = ws->fd, .events = want };
        if (poll(&p, 1, left) < 0 && errno != EINTR) return false;
    }
    return true;
}

//------------------------------------------------------------------------------
// Frames out
//------------------------------------------------------------------------------

static bool send_frame(struct kp_ws* ws, uint8_t opcode, const void* data, size_t len,
    uint32_t timeout_ms) {
    uint8_t* frame = malloc(len + 14);
    if (!frame) return false;
    size_t n = 0;
    frame[n++] = (uint8_t)(0x80 | opcode);  // FIN: one frame per message
    if (len < 126) {
        frame[n++] = (uint8_t)(0x80 | len);
    }
    else if (len <= 0xFFFF) {
        frame[n++] = 0x80 | 126;
        frame[n++] = (uint8_t)(len >> 8);
        frame[n++] = (uint8_t)len;
    }
    else {
        frame[n++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) frame[n++] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof(mask)) != 1) {
        const uint32_t r = kp_random();
        memcpy(mask, &r, sizeof(mask));
    }
    memcpy(frame + n, mask, 4);
    n += 4;
    const uint8_t* src = data;
    for (size_t i = 0; i < len; i++) frame[n + i] = src[i] ^ mask[i & 3];
    n += len;

    const int64_t deadline = kp_monotonic_us() + (int64_t)timeout_ms * 1000;
    pthread_mutex_lock(&ws->io_lock);
    bool ok = ws->fd >= 0 && io_write_all(ws, frame, n, deadline);
    if (!ok && ws->fd >= 0) {
        // A half-written frame cannot be recovered: end the connection. The
        // connection thread sees the shutdown and reports the disconnect.
        atomic_store(&ws->tx_failed, true);
        shutdown(ws->fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&ws->io_lock);
    free(frame);
    return ok;
}

//------------------------------------------------------------------------------
// Connect: TCP, TLS, HTTP upgrade
//------------------------------------------------------------------------------

static bool tcp_connect(struct kp_ws* ws, kp_ws_disconnect_info_t* info) {
    char port[8];
    snprintf(port, sizeof(port), "%d", ws->port);
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo* list = NULL;
    const int gai = getaddrinfo(ws->host, port, &hints, &list);
    if (gai != 0 || !list) {
        KP_LOGW(TAG, "cannot resolve %s: %s", ws->host, gai_strerror(gai));
        info->fail_class = KP_WS_FAIL_LINK;
        return false;
    }

    const int64_t deadline = kp_monotonic_us() + (int64_t)CONNECT_TIMEOUT_MS * 1000;
    int last_errno = 0;
    for (struct addrinfo* a = list; a; a = a->ai_next) {
        if (atomic_load(&ws->closing)) break;
        const int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }
        set_nonblocking(fd);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#if defined(SO_NOSIGPIPE)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#if defined(TCP_KEEPIDLE)
        int idle = 30, intvl = 10, cnt = 4;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif

        pthread_mutex_lock(&ws->io_lock);
        ws->fd = fd;
        pthread_mutex_unlock(&ws->io_lock);
        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            const int w = wait_fd(ws, POLLOUT, ms_left(deadline));
            if (w == 1) {
                int err = 0;
                socklen_t el = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                rc = err ? -1 : 0;
                errno = err;
            }
            else {
                rc = -1;
                errno = (w == 0) ? ETIMEDOUT : ECANCELED;
            }
        }
        if (rc == 0) {
            freeaddrinfo(list);
            return true;
        }
        last_errno = errno;
        pthread_mutex_lock(&ws->io_lock);
        close(fd);
        ws->fd = -1;
        pthread_mutex_unlock(&ws->io_lock);
        if (ms_left(deadline) == 0) break;
    }
    freeaddrinfo(list);
    info->sock_errno = last_errno;
    info->fail_class = classify_errno(last_errno);
    if (info->fail_class == KP_WS_FAIL_UNKNOWN) info->fail_class = KP_WS_FAIL_LINK;
    return false;
}

static bool tls_connect(struct kp_ws* ws, kp_ws_disconnect_info_t* info) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    ws->ctx = SSL_CTX_new(TLS_client_method());
    if (!ws->ctx) {
        info->fail_class = KP_WS_FAIL_UNKNOWN;
        return false;
    }
    SSL_CTX_set_min_proto_version(ws->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ws->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    const int roots = cfg->ca_file
        ? SSL_CTX_load_verify_locations(ws->ctx, cfg->ca_file, NULL)
        : SSL_CTX_set_default_verify_paths(ws->ctx);
    if (roots != 1) {
        KP_LOGE(TAG, "cannot load the trusted roots%s%s", cfg->ca_file ? " from " : "",
            cfg->ca_file ? cfg->ca_file : "");
        info->fail_class = KP_WS_FAIL_UNKNOWN;
        return false;
    }

    if (ws->cert) {
        // The whole chain goes into the handshake: a server that pins a root
        // above our issuer needs every intermediate to build the path.
        if (SSL_CTX_use_certificate(ws->ctx, ws->cert) != 1) {
            KP_LOGE(TAG, "the client certificate was refused by the TLS stack");
            info->fail_class = KP_WS_FAIL_UNKNOWN;
            return false;
        }
        for (int i = 0; ws->chain && i < sk_X509_num(ws->chain); i++) {
            SSL_CTX_add1_chain_cert(ws->ctx, sk_X509_value(ws->chain, i));
        }
        if (!ws->pkey || SSL_CTX_use_PrivateKey(ws->ctx, ws->pkey) != 1) {
            KP_LOGE(TAG, "the private key does not belong to the client certificate (or cannot be used)");
            info->tls_err = (int)ERR_peek_last_error();
            info->fail_class = KP_WS_FAIL_UNKNOWN;
            return false;
        }
    }

    ws->ssl = SSL_new(ws->ctx);
    if (!ws->ssl) {
        info->fail_class = KP_WS_FAIL_UNKNOWN;
        return false;
    }
    SSL_set_fd(ws->ssl, ws->fd);
    SSL_set_tlsext_host_name(ws->ssl, ws->host);
    SSL_set1_host(ws->ssl, ws->host);

    const int64_t deadline = kp_monotonic_us() + (int64_t)CONNECT_TIMEOUT_MS * 1000;
    for (;;) {
        ERR_clear_error();
        const int rc = SSL_connect(ws->ssl);
        if (rc == 1) return true;
        const int err = SSL_get_error(ws->ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            const int w = wait_fd(ws, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, ms_left(deadline));
            if (w == 1) continue;
            info->fail_class = KP_WS_FAIL_LINK;  // nothing came back in time (or we are closing)
            info->sock_errno = ETIMEDOUT;
            return false;
        }

        info->tls_err = (int)ERR_peek_last_error();
        const long verify = SSL_get_verify_result(ws->ssl);
        if (verify != X509_V_OK) {
            KP_LOGW(TAG, "server certificate rejected: %s", X509_verify_cert_error_string(verify));
            info->fail_class = KP_WS_FAIL_SERVER;
        }
        else if (err == SSL_ERROR_SYSCALL && errno != 0) {
            info->sock_errno = errno;
            info->fail_class = classify_errno(errno);
        }
        else {
            // An alert, a protocol error or a clean EOF: the peer talked.
            char msg[160];
            ERR_error_string_n(ERR_peek_last_error(), msg, sizeof(msg));
            KP_LOGW(TAG, "TLS handshake failed: %s", msg);
            info->fail_class = KP_WS_FAIL_SERVER;
        }
        return false;
    }
}

static bool header_value(const char* headers, const char* name, char* out, size_t out_size) {
    const size_t nl = strlen(name);
    for (const char* line = headers; line && *line; ) {
        const char* end = strstr(line, "\r\n");
        if (!end) break;
        if ((size_t)(end - line) > nl && strncasecmp(line, name, nl) == 0 && line[nl] == ':') {
            const char* v = line + nl + 1;
            while (v < end && (*v == ' ' || *v == '\t')) v++;
            size_t len = (size_t)(end - v);
            while (len > 0 && (v[len - 1] == ' ' || v[len - 1] == '\t')) len--;
            if (len >= out_size) len = out_size - 1;
            memcpy(out, v, len);
            out[len] = '\0';
            return true;
        }
        line = end + 2;
    }
    return false;
}

static bool http_upgrade(struct kp_ws* ws, kp_ws_disconnect_info_t* info) {
    uint8_t nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        for (size_t i = 0; i < sizeof(nonce); i += 4) {
            const uint32_t r = kp_random();
            memcpy(nonce + i, &r, 4);
        }
    }
    char key[32];
    EVP_EncodeBlock((unsigned char*)key, nonce, sizeof(nonce));

    const size_t req_cap = 512 + strlen(ws->host) + strlen(ws->path) +
        (ws->bearer ? strlen(ws->bearer) : 0) + (ws->protocols ? strlen(ws->protocols) : 0);
    char* req = malloc(req_cap);
    if (!req) return false;
    const bool default_port = ws->port == (ws->tls ? 443 : 80);
    char hostport[300];
    if (default_port) snprintf(hostport, sizeof(hostport), "%s", ws->host);
    else snprintf(hostport, sizeof(hostport), "%s:%d", ws->host, ws->port);
    int n = snprintf(req, req_cap,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: koios-sdk-linux\r\n",
        ws->path, hostport, key);
    if (ws->bearer) n += snprintf(req + n, req_cap - (size_t)n, "Authorization: Bearer %s\r\n", ws->bearer);
    if (ws->protocols) n += snprintf(req + n, req_cap - (size_t)n, "Sec-WebSocket-Protocol: %s\r\n", ws->protocols);
    n += snprintf(req + n, req_cap - (size_t)n, "\r\n");

    const int64_t deadline = kp_monotonic_us() + (int64_t)CONNECT_TIMEOUT_MS * 1000;
    pthread_mutex_lock(&ws->io_lock);
    const bool sent = io_write_all(ws, (const uint8_t*)req, (size_t)n, deadline);
    pthread_mutex_unlock(&ws->io_lock);
    free(req);
    if (!sent) {
        info->fail_class = KP_WS_FAIL_LINK;
        return false;
    }

    // Read the response head. Bytes after it already belong to the first frame.
    char* end = NULL;
    while (!end) {
        if (ws->in_len >= MAX_HANDSHAKE_BYTES) {
            info->fail_class = KP_WS_FAIL_SERVER;
            return false;
        }
        short want;
        bool eof;
        pthread_mutex_lock(&ws->io_lock);
        const int got = io_read(ws, ws->in_buf + ws->in_len, IN_BUF_SIZE - 1 - ws->in_len, &want, &eof);
        pthread_mutex_unlock(&ws->io_lock);
        if (got < 0) {
            info->fail_class = eof ? KP_WS_FAIL_SERVER : classify_errno(errno);
            info->sock_errno = eof ? 0 : errno;
            return false;
        }
        if (got == 0) {
            if (wait_fd(ws, want, ms_left(deadline)) != 1) {
                info->fail_class = KP_WS_FAIL_LINK;
                info->sock_errno = ETIMEDOUT;
                return false;
            }
            continue;
        }
        ws->in_len += (size_t)got;
        ws->in_buf[ws->in_len] = '\0';
        end = strstr((char*)ws->in_buf, "\r\n\r\n");
    }

    const size_t head_len = (size_t)(end - (char*)ws->in_buf) + 4;
    end[2] = '\0';  // keep the last header's CRLF, cut the blank line

    int status = 0;
    if (sscanf((char*)ws->in_buf, "HTTP/%*d.%*d %d", &status) != 1) status = 0;
    info->handshake_status = status;

    bool ok = (status == 101);
    if (ok) {
        char accept[64] = "", expect[64], concat[96];
        unsigned char sha[EVP_MAX_MD_SIZE];
        unsigned int sha_len = 0;
        snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
        EVP_Digest(concat, strlen(concat), sha, &sha_len, EVP_sha1(), NULL);
        EVP_EncodeBlock((unsigned char*)expect, sha, (int)sha_len);
        const char* headers = strstr((char*)ws->in_buf, "\r\n");
        ok = headers && header_value(headers + 2, "Sec-WebSocket-Accept", accept, sizeof(accept)) &&
            strcmp(accept, expect) == 0;
        if (!ok) KP_LOGW(TAG, "upgrade answered 101 without a valid Sec-WebSocket-Accept");
    }
    else {
        KP_LOGW(TAG, "upgrade refused: HTTP %d", status);
    }

    // Shift what follows the head to the front of the buffer.
    memmove(ws->in_buf, ws->in_buf + head_len, ws->in_len - head_len);
    ws->in_len -= head_len;

    if (!ok) info->fail_class = KP_WS_FAIL_SERVER;  // an HTTP answer proves the link
    return ok;
}

//------------------------------------------------------------------------------
// Frames in
//------------------------------------------------------------------------------

static void msg_reset(struct kp_ws* ws) {
    free(ws->msg_buf);
    ws->msg_buf = NULL;
    ws->msg_len = ws->msg_cap = 0;
    ws->msg_active = false;
    ws->msg_dropping = false;
}

static void emit(struct kp_ws* ws, kp_ws_event_type_t ev, const uint8_t* data, size_t len) {
    if (atomic_load(&ws->closing)) return;
    ws->on_event(ws->event_arg, ev, data, len);
}

// A whole frame has been received. Returns false when the connection ends
// (close frame); *info then says why.
static bool frame_complete(struct kp_ws* ws, kp_ws_disconnect_info_t* info) {
    switch (ws->cur_opcode) {
    case 0x9:  // ping: answer with the same payload
        send_frame(ws, 0xA, ws->ctl_buf, ws->ctl_len, 5000);
        return true;
    case 0xA:  // pong
        return true;
    case 0x8: {  // close: echo the status and stop
        const unsigned code = ws->ctl_len >= 2 ? (unsigned)(ws->ctl_buf[0] << 8 | ws->ctl_buf[1]) : 1005;
        KP_LOGI(TAG, "server closed the connection (code %u%s%.*s)", code,
            ws->ctl_len > 2 ? ": " : "", (int)(ws->ctl_len > 2 ? ws->ctl_len - 2 : 0),
            ws->ctl_len > 2 ? (const char*)ws->ctl_buf + 2 : "");
        send_frame(ws, 0x8, ws->ctl_buf, ws->ctl_len >= 2 ? 2 : 0, 2000);
        info->fail_class = KP_WS_FAIL_SERVER;
        return false;
    }
    case 0x0:
    case 0x1:
    case 0x2:
        if (!ws->cur_fin) return true;  // more fragments follow
        if (!ws->msg_active) return true;
        if (ws->msg_dropping) {
            msg_reset(ws);
            return true;
        }
        if (ws->msg_len > 0 && ws->msg_buf) {
            ws->msg_buf[ws->msg_len] = '\0';
            emit(ws, ws->msg_is_text ? KP_WS_EV_MSG_TEXT : KP_WS_EV_MSG_BINARY, ws->msg_buf, ws->msg_len);
        }
        msg_reset(ws);
        return true;
    default:
        return true;  // reserved opcode: ignored
    }
}

// Take what the header says about the frame that starts now.
static void frame_begin(struct kp_ws* ws) {
    ws->cur_offset = 0;
    ws->ctl_len = 0;
    if (ws->cur_control) return;
    if (ws->cur_opcode == 0x1 || ws->cur_opcode == 0x2) {
        msg_reset(ws);
        ws->msg_active = true;
        ws->msg_is_text = (ws->cur_opcode == 0x1);
    }
    else if (ws->cur_opcode == 0x0 && !ws->msg_active) {
        KP_LOGW(TAG, "continuation frame without a start, dropping");
        ws->msg_dropping = true;
        ws->msg_active = true;  // swallow it, and reset on FIN
    }
    if (!ws->msg_dropping && ws->msg_len + ws->cur_remaining > ws->max_rx_size) {
        KP_LOGE(TAG, "message too large: %llu > %u bytes",
            (unsigned long long)(ws->msg_len + ws->cur_remaining), (unsigned)ws->max_rx_size);
        free(ws->msg_buf);
        ws->msg_buf = NULL;
        ws->msg_len = ws->msg_cap = 0;
        ws->msg_dropping = true;
    }
    if (!ws->msg_dropping) {
        const size_t need = ws->msg_len + (size_t)ws->cur_remaining + 1;
        if (need > ws->msg_cap) {
            uint8_t* grown = realloc(ws->msg_buf, need);
            if (!grown) {
                KP_LOGE(TAG, "alloc failed: %u bytes", (unsigned)need);
                free(ws->msg_buf);
                ws->msg_buf = NULL;
                ws->msg_len = ws->msg_cap = 0;
                ws->msg_dropping = true;
            }
            else {
                ws->msg_buf = grown;
                ws->msg_cap = need;
            }
        }
    }
}

// Consume as much of in_buf as forms whole steps. Returns false when the
// connection must end.
static bool parse_input(struct kp_ws* ws, kp_ws_disconnect_info_t* info) {
    size_t pos = 0;
    bool alive = true;
    while (alive) {
        const size_t avail = ws->in_len - pos;
        if (ws->state == ST_HEADER) {
            if (avail < 2) break;
            const uint8_t* h = ws->in_buf + pos;
            const uint8_t len7 = h[1] & 0x7F;
            const bool masked = (h[1] & 0x80) != 0;
            const size_t hdr_len = 2 + (len7 == 126 ? 2 : len7 == 127 ? 8 : 0) + (masked ? 4 : 0);
            if (avail < hdr_len) break;

            uint64_t plen = len7;
            size_t off = 2;
            if (len7 == 126) {
                plen = (uint64_t)h[2] << 8 | h[3];
                off = 4;
            }
            else if (len7 == 127) {
                plen = 0;
                for (int i = 0; i < 8; i++) plen = plen << 8 | h[2 + i];
                off = 10;
            }
            if (masked) memcpy(ws->cur_mask, h + off, 4);

            ws->cur_fin = (h[0] & 0x80) != 0;
            ws->cur_opcode = h[0] & 0x0F;
            ws->cur_masked = masked;
            ws->cur_control = ws->cur_opcode >= 0x8;
            ws->cur_remaining = plen;
            if (ws->cur_control && (plen > sizeof(ws->ctl_buf) || !ws->cur_fin)) {
                KP_LOGW(TAG, "malformed control frame, closing");
                info->fail_class = KP_WS_FAIL_SERVER;
                return false;
            }
            frame_begin(ws);
            pos += hdr_len;
            ws->state = ST_PAYLOAD;
        }

        if (ws->state == ST_PAYLOAD) {
            size_t take = ws->in_len - pos;
            if (take > ws->cur_remaining) take = (size_t)ws->cur_remaining;
            if (take > 0) {
                uint8_t* p = ws->in_buf + pos;
                if (ws->cur_masked) {
                    for (size_t i = 0; i < take; i++) p[i] ^= ws->cur_mask[(ws->cur_offset + i) & 3];
                }
                if (ws->cur_control) {
                    memcpy(ws->ctl_buf + ws->ctl_len, p, take);
                    ws->ctl_len += take;
                }
                else if (!ws->msg_dropping && ws->msg_buf) {
                    memcpy(ws->msg_buf + ws->msg_len, p, take);
                    ws->msg_len += take;
                }
                ws->cur_offset += take;
                ws->cur_remaining -= take;
                pos += take;
            }
            if (ws->cur_remaining > 0) break;  // need more bytes
            ws->state = ST_HEADER;
            alive = frame_complete(ws, info);
        }
    }
    if (pos > 0) {
        memmove(ws->in_buf, ws->in_buf + pos, ws->in_len - pos);
        ws->in_len -= pos;
    }
    return alive;
}

static void run(struct kp_ws* ws, kp_ws_disconnect_info_t* info) {
    ws->last_rx_us = ws->last_ping_us = kp_monotonic_us();

    // The upgrade response may have carried the first frames along.
    if (!parse_input(ws, info)) return;

    for (;;) {
        if (atomic_load(&ws->closing)) return;

        // Drain everything the socket (and the TLS layer) has.
        bool drained = false;
        short want = POLLIN;
        while (!drained) {
            bool eof;
            pthread_mutex_lock(&ws->io_lock);
            const int n = io_read(ws, ws->in_buf + ws->in_len, IN_BUF_SIZE - ws->in_len, &want, &eof);
            const int saved_errno = errno;
            pthread_mutex_unlock(&ws->io_lock);
            if (n < 0) {
                if (atomic_load(&ws->tx_failed)) {
                    info->fail_class = KP_WS_FAIL_LINK;  // our own write gave up
                    info->sock_errno = EPIPE;
                }
                else if (eof) {
                    info->fail_class = KP_WS_FAIL_SERVER;  // the peer closed: it is reachable
                }
                else {
                    info->sock_errno = saved_errno;
                    info->fail_class = classify_errno(saved_errno);
                    if (ws->ssl && info->fail_class == KP_WS_FAIL_UNKNOWN) {
                        info->tls_err = (int)ERR_peek_last_error();
                        info->fail_class = KP_WS_FAIL_SERVER;  // a TLS-level error is an answer
                    }
                }
                return;
            }
            if (n == 0) {
                drained = true;
                break;
            }
            ws->in_len += (size_t)n;
            ws->last_rx_us = kp_monotonic_us();
            if (!parse_input(ws, info)) return;
        }

        const int64_t now = kp_monotonic_us();
        if (now - ws->last_rx_us >= RX_TIMEOUT_US) {
            KP_LOGW(TAG, "nothing received for %llds, giving up on the connection",
                (long long)(RX_TIMEOUT_US / 1000000));
            info->fail_class = KP_WS_FAIL_LINK;
            info->sock_errno = ETIMEDOUT;
            return;
        }
        if (now - ws->last_ping_us >= PING_INTERVAL_US) {
            ws->last_ping_us = now;
            if (!send_frame(ws, 0x9, NULL, 0, 5000)) continue;  // the read path reports it
        }

        int64_t next = ws->last_ping_us + PING_INTERVAL_US;
        if (ws->last_rx_us + RX_TIMEOUT_US < next) next = ws->last_rx_us + RX_TIMEOUT_US;
        int wait_ms = ms_left(next);
        if (wait_ms < 10) wait_ms = 10;
        if (wait_fd(ws, want, wait_ms) < 0 && atomic_load(&ws->closing)) return;
    }
}

//------------------------------------------------------------------------------
// Lifetime
//------------------------------------------------------------------------------

static void ws_free(struct kp_ws* ws) {
    msg_reset(ws);
    free(ws->in_buf);
    free(ws->host);
    free(ws->path);
    free(ws->bearer);
    free(ws->protocols);
    X509_free(ws->cert);
    sk_X509_pop_free(ws->chain, X509_free);
    EVP_PKEY_free(ws->pkey);
    if (ws->wake_pipe[0] >= 0) close(ws->wake_pipe[0]);
    if (ws->wake_pipe[1] >= 0) close(ws->wake_pipe[1]);
    pthread_mutex_destroy(&ws->io_lock);
    pthread_mutex_destroy(&ws->done_lock);
    pthread_cond_destroy(&ws->done_cond);
    free(ws);
}

static void ws_release(struct kp_ws* ws) {
    if (atomic_fetch_sub(&ws->owners, 1) == 1) ws_free(ws);
}

static void* ws_thread(void* arg) {
    struct kp_ws* ws = arg;
#if defined(__APPLE__)
    pthread_setname_np("koios_ws");
#else
    pthread_setname_np(pthread_self(), "koios_ws");
#endif

    kp_ws_disconnect_info_t info = { 0 };
    bool up = tcp_connect(ws, &info);
    if (up && ws->tls) up = tls_connect(ws, &info);
    if (up) up = http_upgrade(ws, &info);

    if (up && !atomic_load(&ws->closing)) {
        atomic_store(&ws->connected, true);
        info.was_connected = true;
        emit(ws, KP_WS_EV_CONNECTED, NULL, 0);
        run(ws, &info);
        atomic_store(&ws->connected, false);
    }

    if (!atomic_load(&ws->closing)) {
        KP_LOGW(TAG, "disconnected (%s%s: handshake=%d tls=0x%x errno=%d)",
            class_name(info.fail_class), info.was_connected ? ", was connected" : "",
            info.handshake_status, (unsigned)info.tls_err, info.sock_errno);
        emit(ws, KP_WS_EV_DISCONNECTED, (const uint8_t*)&info, sizeof(info));
    }

    // Tear the transport down under io_lock so a sender never sees a
    // half-freed connection.
    pthread_mutex_lock(&ws->io_lock);
    if (ws->ssl) {
        SSL_free(ws->ssl);
        ws->ssl = NULL;
    }
    if (ws->ctx) {
        SSL_CTX_free(ws->ctx);
        ws->ctx = NULL;
    }
    if (ws->fd >= 0) {
        close(ws->fd);
        ws->fd = -1;
    }
    pthread_mutex_unlock(&ws->io_lock);

    pthread_mutex_lock(&ws->done_lock);
    ws->done = true;
    pthread_cond_broadcast(&ws->done_cond);
    pthread_mutex_unlock(&ws->done_lock);
    ws_release(ws);
    return NULL;
}

// ws[s]://host[:port][/path]
static bool parse_url(struct kp_ws* ws, const char* url) {
    const char* p;
    if (strncmp(url, "wss://", 6) == 0) { ws->tls = true; p = url + 6; }
    else if (strncmp(url, "ws://", 5) == 0) { ws->tls = false; p = url + 5; }
    else return false;

    const char* path = strchr(p, '/');
    const size_t auth_len = path ? (size_t)(path - p) : strlen(p);
    char auth[280];
    if (auth_len == 0 || auth_len >= sizeof(auth)) return false;
    memcpy(auth, p, auth_len);
    auth[auth_len] = '\0';

    ws->port = ws->tls ? 443 : 80;
    char* host = auth;
    char* port = NULL;
    if (auth[0] == '[') {  // IPv6 literal
        char* close_br = strchr(auth, ']');
        if (!close_br) return false;
        *close_br = '\0';
        host = auth + 1;
        if (close_br[1] == ':') port = close_br + 2;
    }
    else {
        port = strrchr(auth, ':');
        if (port) *port++ = '\0';
    }
    if (port && *port) {
        ws->port = atoi(port);
        if (ws->port <= 0 || ws->port > 65535) return false;
    }
    ws->host = strdup(host);
    ws->path = strdup(path ? path : "/");
    return ws->host && ws->path && ws->host[0];
}

// The PEM handed over by kp_identity: the leaf first, intermediates after it.
static bool load_client_chain(struct kp_ws* ws, const char* pem, size_t len) {
    BIO* bio = BIO_new_mem_buf(pem, (int)strnlen(pem, len));
    if (!bio) return false;
    ws->cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (ws->cert) {
        ws->chain = sk_X509_new_null();
        X509* extra;
        while (ws->chain && (extra = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
            sk_X509_push(ws->chain, extra);
        }
        ERR_clear_error();  // the read past the last certificate ends in an error
    }
    BIO_free(bio);
    return ws->cert != NULL;
}

kp_ws_t kp_ws_open(const kp_ws_config_t* cfg) {
    if (!cfg || !cfg->url || !cfg->on_event) return NULL;

    struct kp_ws* ws = calloc(1, sizeof(*ws));
    if (!ws) return NULL;
    ws->fd = -1;
    ws->wake_pipe[0] = ws->wake_pipe[1] = -1;
    pthread_mutex_init(&ws->io_lock, NULL);
    pthread_mutex_init(&ws->done_lock, NULL);
    kp_linux_cond_init(&ws->done_cond);
    atomic_init(&ws->owners, 1);
    ws->on_event = cfg->on_event;
    ws->event_arg = cfg->event_arg;
    ws->max_rx_size = cfg->max_rx_size ? cfg->max_rx_size : (16 * 1024);
    ws->in_buf = malloc(IN_BUF_SIZE);

    bool ok = ws->in_buf && parse_url(ws, cfg->url) && pipe(ws->wake_pipe) == 0;
    if (ok) {
        set_nonblocking(ws->wake_pipe[0]);
        set_nonblocking(ws->wake_pipe[1]);
    }
    if (ok && cfg->bearer) {
        ws->bearer = strdup(cfg->bearer);
        ok = ws->bearer != NULL;
    }
    if (ok && cfg->protocols) {
        ws->protocols = strdup(cfg->protocols);
        ok = ws->protocols != NULL;
    }
    if (ok && cfg->client_cert_pem) {
        const kp_linux_key_ctx_t* key = cfg->client_key_ctx;
        ok = key && key->pkey && load_client_chain(ws, cfg->client_cert_pem, cfg->client_cert_len);
        if (ok) {
            EVP_PKEY_up_ref(key->pkey);
            ws->pkey = key->pkey;
        }
        else {
            KP_LOGE(TAG, "client certificate or key unusable");
        }
    }
    if (!ok) {
        ws_free(ws);
        return NULL;
    }

    atomic_store(&ws->owners, 2);  // the caller and the thread
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    const int rc = pthread_create(&thread, &attr, ws_thread, ws);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        atomic_store(&ws->owners, 1);
        ws_free(ws);
        return NULL;
    }
    return ws;
}

bool kp_ws_is_connected(kp_ws_t ws) {
    return ws && atomic_load(&ws->connected) && !atomic_load(&ws->closing);
}

bool kp_ws_send(kp_ws_t ws, const void* data, size_t len, bool binary, uint32_t timeout_ms) {
    if (!ws || !data || atomic_load(&ws->closing) || !atomic_load(&ws->connected)) return false;
    return send_frame(ws, binary ? 0x2 : 0x1, data, len, timeout_ms);
}

bool kp_ws_close_bounded(kp_ws_t ws, uint32_t timeout_ms) {
    if (!ws) return true;
    // Say goodbye while the connection is still ours to write on: the peer
    // then sees a close, not a broken connection. Everything sent before it is
    // already in the socket and is delivered first.
    if (atomic_load(&ws->connected)) send_frame(ws, 0x8, "\x03\xe8", 2, 1000);
    // Mask events: the core has dropped its handle.
    atomic_store(&ws->closing, true);
    const char wake = 1;
    if (write(ws->wake_pipe[1], &wake, 1) < 0) { /* the pipe is full: the thread is awake */ }
    pthread_mutex_lock(&ws->io_lock);
    if (ws->fd >= 0) shutdown(ws->fd, SHUT_RDWR);
    pthread_mutex_unlock(&ws->io_lock);

    const int64_t deadline = kp_monotonic_us() + (int64_t)timeout_ms * 1000;
    pthread_mutex_lock(&ws->done_lock);
    while (!ws->done) {
        if (timeout_ms == KP_WAIT_FOREVER) {
            kp_linux_cond_wait(&ws->done_cond, &ws->done_lock, KP_WAIT_FOREVER);
            continue;
        }
        const int left = ms_left(deadline);
        if (left == 0) break;
        kp_linux_cond_wait(&ws->done_cond, &ws->done_lock, (uint32_t)left);
    }
    const bool done = ws->done;
    pthread_mutex_unlock(&ws->done_lock);

    if (!done) {
        KP_LOGE(TAG, "connection thread did not exit within %u ms (a callback is blocking it?); "
            "detaching, it frees itself when it returns", (unsigned)timeout_ms);
    }
    ws_release(ws);
    return done;
}

void kp_ws_close(kp_ws_t ws) {
    kp_ws_close_bounded(ws, KP_WAIT_FOREVER);
}
