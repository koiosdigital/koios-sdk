#include "console_stream.h"

#include "koios/port/kp_identity.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_websocket.h"
#include "kp_linux.h"

#include <cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

static const char* TAG = "console";

#define TARGET_CONNECT_TIMEOUT_MS 5000
#define SEND_TIMEOUT_MS           30000

typedef struct {
    ks_config_t cfg;
    kp_ws_t ws;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool started;    // `ready` went out (device) or came in (operator): the stream runs
    bool finished;
    char reason[200];

    int in_fd, out_fd;
    bool own_fds;    // device: both are the target's socket, closed here
    pid_t target_pid;  // device, an exec: target: the program started for the session

    // local -> gateway
    unsigned long long sent, acked;
    // gateway -> local
    unsigned long long received, ack_sent;

    pthread_t reader;
    bool reader_started;
} ks_t;

static void finish(ks_t* k, const char* reason) {
    pthread_mutex_lock(&k->lock);
    if (!k->finished) {
        k->finished = true;
        if (reason) snprintf(k->reason, sizeof(k->reason), "%s", reason);
        pthread_cond_broadcast(&k->cond);
    }
    pthread_mutex_unlock(&k->lock);
}

static bool write_all(int fd, const uint8_t* data, size_t len) {
    while (len > 0) {
        const ssize_t n = write(fd, data, len);
        if (n > 0) {
            data += n;
            len -= (size_t)n;
        }
        else if (n < 0 && errno == EINTR) {
            continue;
        }
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            poll(&p, 1, 1000);
        }
        else {
            return false;
        }
    }
    return true;
}

// The local stream into the session, a window at a time.
static void* reader_thread(void* arg) {
    ks_t* k = arg;
    uint8_t* buf = malloc(KS_CHUNK);
    while (buf) {
        pthread_mutex_lock(&k->lock);
        while (!k->finished && k->sent - k->acked >= KS_WINDOW) {
            kp_linux_cond_wait(&k->cond, &k->lock, 1000);
        }
        const bool done = k->finished;
        pthread_mutex_unlock(&k->lock);
        if (done) break;

        const ssize_t n = read(k->in_fd, buf, KS_CHUNK);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            finish(k, NULL);  // the local side closed: a normal end
            break;
        }
        if (!kp_ws_send(k->ws, buf, (size_t)n, true, SEND_TIMEOUT_MS)) {
            finish(k, "the connection to the gateway was lost");
            break;
        }
        pthread_mutex_lock(&k->lock);
        k->sent += (unsigned long long)n;
        pthread_mutex_unlock(&k->lock);
    }
    free(buf);
    return NULL;
}

static void start_stream(ks_t* k) {
    pthread_mutex_lock(&k->lock);
    const bool first = !k->started;
    k->started = true;
    pthread_mutex_unlock(&k->lock);
    if (first) k->reader_started = pthread_create(&k->reader, NULL, reader_thread, k) == 0;
    if (first && !k->reader_started) finish(k, "out of resources");
}

// "host:port" -> a connected socket, or -1.
static int connect_tcp(const char* address) {
    char host[96];
    const char* colon = strrchr(address, ':');
    if (!colon || colon == address || (size_t)(colon - address) >= sizeof(host)) return -1;
    memcpy(host, address, (size_t)(colon - address));
    host[colon - address] = '\0';
    // [::1]:22
    char* h = host;
    const size_t hl = strlen(h);
    if (h[0] == '[' && hl >= 2 && h[hl - 1] == ']') {
        h[hl - 1] = '\0';
        h++;
    }

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo* list = NULL;
    if (getaddrinfo(h, colon + 1, &hints, &list) != 0) return -1;
    int fd = -1;
    for (struct addrinfo* a = list; a && fd < 0; a = a->ai_next) {
        const int s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s < 0) continue;
        const int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        fcntl(s, F_SETFD, FD_CLOEXEC);
        int rc = connect(s, a->ai_addr, a->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            struct pollfd p = { .fd = s, .events = POLLOUT };
            int err = ETIMEDOUT;
            socklen_t el = sizeof(err);
            if (poll(&p, 1, TARGET_CONNECT_TIMEOUT_MS) == 1) getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el);
            rc = err ? -1 : 0;
        }
        if (rc == 0) {
            fcntl(s, F_SETFL, flags);  // blocking again: the pumps block on it
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            fd = s;
        }
        else {
            close(s);
        }
    }
    freeaddrinfo(list);
    return fd;
}

// "/path" -> a connected Unix stream socket, or -1.
static int connect_unix(const char* path) {
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(addr.sun_path)) return -1;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    const int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    fcntl(s, F_SETFD, FD_CLOEXEC);
    if (connect(s, (const struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

// "/path/to/program arg ..." -> one end of a socket pair whose other end is
// the program's standard input and output, or -1. Arguments are split at
// spaces; there is no quoting.
static int spawn_target(const char* command, pid_t* pid_out) {
    char line[256];
    if (strlen(command) >= sizeof(line)) return -1;
    snprintf(line, sizeof(line), "%s", command);
    char* argv[16];
    int argc = 0;
    char* save = NULL;
    for (char* word = strtok_r(line, " ", &save); word && argc < 15; word = strtok_r(NULL, " ", &save)) {
        argv[argc++] = word;
    }
    argv[argc] = NULL;
    if (argc == 0 || argv[0][0] != '/') return -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, sv[1], 0);
    posix_spawn_file_actions_adddup2(&actions, sv[1], 1);
    if (sv[1] > 2) posix_spawn_file_actions_addclose(&actions, sv[1]);
    pid_t pid = 0;
    const int rc = posix_spawn(&pid, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(sv[1]);
    if (rc != 0) {
        close(sv[0]);
        return -1;
    }
    *pid_out = pid;
    return sv[0];
}

// The device's end of the stream, from the target's address in the device's
// own configuration:
//
//   host:port         a TCP connection (an sshd, a service on this device)
//   unix:/path        a Unix stream socket (a socket-activated service)
//   exec:/path arg…   a program started for this session, with the stream as
//                     its standard input and output
static int connect_target(const char* address, pid_t* pid_out) {
    int fd;
    if (strncmp(address, "unix:", 5) == 0) fd = connect_unix(address + 5);
    else if (strncmp(address, "exec:", 5) == 0) fd = spawn_target(address + 5, pid_out);
    else fd = connect_tcp(address);
#if defined(SO_NOSIGPIPE)
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif
    return fd;
}

// An exec: target's program has lost its stream and ends by itself; make sure.
static void reap_target(pid_t pid) {
    int status;
    for (int i = 0; i < 150; i++) {  // 3 s
        if (waitpid(pid, &status, WNOHANG) != 0) return;
        usleep(20 * 1000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
}

static void send_text(ks_t* k, const char* json) {
    kp_ws_send(k->ws, json, strlen(json), false, 5000);
}

static void on_text(ks_t* k, const uint8_t* data, size_t len) {
    cJSON* msg = cJSON_ParseWithLength((const char*)data, len);
    const char* type = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "type"));
    if (!type) {
        cJSON_Delete(msg);
        return;
    }

    if (strcmp(type, "ack") == 0) {
        const cJSON* bytes = cJSON_GetObjectItem(msg, "bytes");
        if (cJSON_IsNumber(bytes) && bytes->valuedouble >= 0) {
            pthread_mutex_lock(&k->lock);
            const unsigned long long acked = (unsigned long long)bytes->valuedouble;
            if (acked > k->acked && acked <= k->sent) k->acked = acked;
            pthread_cond_broadcast(&k->cond);
            pthread_mutex_unlock(&k->lock);
        }
    }
    else if (strcmp(type, "start") == 0 && k->cfg.role == KS_ROLE_DEVICE) {
        // The operator is there. Only now is the target connected: an sshd
        // gives a silent client two minutes, and the operator may take longer
        // than that to arrive.
        if (!k->started) {
            const int fd = connect_target(k->cfg.target_address, &k->target_pid);
            if (fd < 0) {
                send_text(k, "{\"type\":\"error\",\"reason\":\"the device could not connect to its target\"}");
                finish(k, "could not connect to the target");
            }
            else {
                k->in_fd = k->out_fd = fd;
                k->own_fds = true;
                send_text(k, "{\"type\":\"ready\"}");
                start_stream(k);
            }
        }
    }
    else if (strcmp(type, "ready") == 0 && k->cfg.role == KS_ROLE_OPERATOR) {
        start_stream(k);
    }
    else if (strcmp(type, "error") == 0) {
        const char* reason = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "reason"));
        finish(k, reason ? reason : "the other end reported an error");
    }
    cJSON_Delete(msg);
}

static void on_binary(ks_t* k, const uint8_t* data, size_t len) {
    if (!k->started || k->out_fd < 0) return;
    if (!write_all(k->out_fd, data, len)) {
        finish(k, NULL);  // the local side closed
        return;
    }
    k->received += len;
    if (k->received - k->ack_sent >= KS_ACK_EVERY) {
        char ack[64];
        snprintf(ack, sizeof(ack), "{\"type\":\"ack\",\"bytes\":%llu}", k->received);
        send_text(k, ack);
        k->ack_sent = k->received;
    }
}

static void on_event(void* arg, kp_ws_event_type_t ev, const uint8_t* data, size_t len) {
    ks_t* k = arg;
    switch (ev) {
    case KP_WS_EV_CONNECTED:
        break;
    case KP_WS_EV_MSG_TEXT:
        on_text(k, data, len);
        break;
    case KP_WS_EV_MSG_BINARY:
        on_binary(k, data, len);
        break;
    case KP_WS_EV_DISCONNECTED: {
        const kp_ws_disconnect_info_t* info =
            (data && len == sizeof(kp_ws_disconnect_info_t)) ? (const kp_ws_disconnect_info_t*)data : NULL;
        const char* why = "the gateway closed the session";
        if (info && !info->was_connected) {
            switch (info->handshake_status) {
            case 401: why = "the gateway asked for a ticket or token and got none"; break;
            case 403: why = "the gateway refused: the ticket is used, expired or wrong"; break;
            case 404: why = "the gateway knows no such session"; break;
            case 409: why = "this end of the session is already taken"; break;
            case 410: why = "the session has already ended"; break;
            default:  why = "could not reach the gateway"; break;
            }
        }
        finish(k, why);
        break;
    }
    }
}

int ks_run(const ks_config_t* cfg, char* reason, size_t reason_size) {
    ks_t* k = calloc(1, sizeof(*k));
    if (!k) return KS_NOT_STARTED;
    k->cfg = *cfg;
    k->in_fd = cfg->role == KS_ROLE_OPERATOR ? cfg->in_fd : -1;
    k->out_fd = cfg->role == KS_ROLE_OPERATOR ? cfg->out_fd : -1;
    pthread_mutex_init(&k->lock, NULL);
    kp_linux_cond_init(&k->cond);

    char* cert = NULL;
    size_t cert_len = 0;
    void* key = NULL;
    kp_ws_config_t ws = {
        .url = cfg->url,
        .bearer = cfg->bearer,
        .protocols = cfg->protocols,
        .max_rx_size = 256 * 1024,
        .on_event = on_event,
        .event_arg = k,
    };
    bool ok = true;
    if (cfg->present_identity) {
        ok = kp_identity_get_client_cert(&cert, &cert_len) == 0 && (key = kp_identity_get_key_ctx()) != NULL;
        ws.client_cert_pem = cert;
        ws.client_cert_len = cert_len + 1;
        ws.client_key_ctx = key;
    }
    if (ok) k->ws = kp_ws_open(&ws);
    if (!k->ws) finish(k, ok ? "could not open the connection to the gateway" : "the device identity is not usable");

    pthread_mutex_lock(&k->lock);
    while (!k->finished) kp_linux_cond_wait(&k->cond, &k->lock, KP_WAIT_FOREVER);
    const bool started = k->started;
    pthread_mutex_unlock(&k->lock);

    // Unblock the reader (the target's socket; an operator's stdin cannot be
    // unblocked, and its process ends right after this returns).
    if (k->own_fds && k->in_fd >= 0) shutdown(k->in_fd, SHUT_RDWR);
    if (k->ws) kp_ws_close_bounded(k->ws, 5000);
    if (k->reader_started && k->own_fds) pthread_join(k->reader, NULL);
    if (k->own_fds && k->in_fd >= 0) close(k->in_fd);
    if (k->target_pid > 0) reap_target(k->target_pid);

    if (reason && reason_size) snprintf(reason, reason_size, "%s", k->reason);
    if (cert) kp_free(cert);
    if (key) kp_identity_release_key_ctx(key);

    const int rc = started ? KS_OK : KS_NOT_STARTED;
    // An operator's reader thread may still sit in read(stdin) and holds `k`:
    // leave it; the process is about to exit.
    if (!(k->reader_started && !k->own_fds)) {
        pthread_mutex_destroy(&k->lock);
        pthread_cond_destroy(&k->cond);
        free(k);
    }
    KP_LOGD(TAG, "session end (%s)", started ? "ran" : "never started");
    return rc;
}
