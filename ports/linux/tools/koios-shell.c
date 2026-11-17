// koios-shell: a login shell on a terminal, for a console session.
//
// The far end of a console session whose target is a shell. koios-agent joins
// the session to this program, either by starting it (`target.shell =
// exec:/usr/libexec/koios/koios-shell`) or by connecting to a socket a service
// manager listens on and starts it from (`target.shell = unix:/run/...`, which
// is how the shell gets to run as another user than the agent; docs/linux.md).
//
// Standard input and output are the session's byte stream. It carries small
// frames in both directions, so that a terminal's size and the shell's exit
// status can travel next to its bytes:
//
//   frame = type (1 byte), length (4 bytes, big-endian), payload
//
//   operator -> shell   1 DATA     what was typed
//                       2 RESIZE   columns, rows (2 bytes each, big-endian)
//   shell -> operator   4 HELLO    {"user","host","shell"} as JSON; once, first
//                       1 DATA     what the terminal shows
//                       3 EXIT     the shell's exit status (4 bytes, big-endian)
//
// A frame of a type this program does not know is skipped. The other end is
// the terminal in the Koios console (app: src/lib/device-console/stream.ts).
//
// The shell is the login shell of the user this program runs as, or of
// --user NAME when it is started as root. It gets a pseudo-terminal and a
// session of its own. When the stream ends the terminal hangs up, and the
// shell and what it started get SIGHUP.

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define F_DATA   1
#define F_RESIZE 2
#define F_EXIT   3
#define F_HELLO  4

#define MAX_PAYLOAD    65536
#define CHUNK          16384
#define FIRST_FRAME_MS 300   // how long the shell waits for the terminal's size before it starts
#define HANGUP_WAIT_MS 2000  // how long a shell gets to go after SIGHUP

static const int s_in = 0;
static const int s_out = 1;
static int s_master = -1;
static volatile sig_atomic_t s_stop;

static void say(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("koios-shell: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void on_stop(int sig) {
    (void)sig;
    s_stop = 1;
}

static void on_child(int sig) {
    (void)sig;  // only there to interrupt poll()
}

static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static bool write_all(int fd, const uint8_t* data, size_t len) {
    while (len > 0) {
        const ssize_t n = write(fd, data, len);
        if (n > 0) {
            data += n;
            len -= (size_t)n;
        }
        else if (n < 0 && errno == EINTR) {
            if (s_stop) return false;
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

static bool send_frame(uint8_t type, const void* payload, uint32_t len) {
    const uint8_t header[5] = { type, (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len };
    return write_all(s_out, header, sizeof(header)) && (len == 0 || write_all(s_out, payload, len));
}

// What the terminal shows, into the stream. 1: something was sent, 0: nothing
// to read right now, -1: the terminal is gone or the stream is.
static int drain_terminal(void) {
    static uint8_t buf[CHUNK];
    const ssize_t n = read(s_master, buf, sizeof(buf));
    if (n > 0) return send_frame(F_DATA, buf, (uint32_t)n) ? 1 : -1;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return -1;  // 0 (macOS) or EIO (Linux): every process has closed the terminal
}

// What was typed, into the terminal. The terminal's input queue is small and
// the shell may be busy printing: keep its output moving while this waits.
static bool type_into_terminal(const uint8_t* data, size_t len) {
    while (len > 0) {
        const ssize_t n = write(s_master, data, len);
        if (n > 0) {
            data += n;
            len -= (size_t)n;
        }
        else if (n < 0 && errno == EINTR) {
            if (s_stop) return false;
        }
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd p = { .fd = s_master, .events = POLLOUT | POLLIN };
            poll(&p, 1, 1000);
            if ((p.revents & POLLIN) && drain_terminal() < 0) return false;
        }
        else {
            return false;
        }
    }
    return true;
}

// The stream's frames as they arrive. False on a frame that cannot be.
static uint8_t s_inbuf[5 + MAX_PAYLOAD];
static size_t s_inlen;

static bool take_frames(void) {
    size_t at = 0;
    while (s_inlen - at >= 5) {
        const uint8_t type = s_inbuf[at];
        const uint32_t len = ((uint32_t)s_inbuf[at + 1] << 24) | ((uint32_t)s_inbuf[at + 2] << 16) |
            ((uint32_t)s_inbuf[at + 3] << 8) | s_inbuf[at + 4];
        if (len > MAX_PAYLOAD) {
            say("a frame of %u bytes: not the console's stream", (unsigned)len);
            return false;
        }
        if (s_inlen - at - 5 < len) break;
        const uint8_t* payload = s_inbuf + at + 5;
        if (type == F_DATA) {
            if (!type_into_terminal(payload, len)) return false;
        }
        else if (type == F_RESIZE && len >= 4) {
            struct winsize ws = {
                .ws_col = (unsigned short)((payload[0] << 8) | payload[1]),
                .ws_row = (unsigned short)((payload[2] << 8) | payload[3]),
            };
            if (ws.ws_col >= 2 && ws.ws_row >= 1 && ws.ws_col <= 1000 && ws.ws_row <= 1000) {
                ioctl(s_master, TIOCSWINSZ, &ws);  // the kernel sends SIGWINCH
            }
        }
        at += 5 + len;
    }
    memmove(s_inbuf, s_inbuf + at, s_inlen - at);
    s_inlen -= at;
    return true;
}

// 1: frames were taken, 0: nothing to read, -1: the stream ended.
static int read_stream(void) {
    const ssize_t n = read(s_in, s_inbuf + s_inlen, sizeof(s_inbuf) - s_inlen);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    if (n <= 0) return -1;
    s_inlen += (size_t)n;
    return take_frames() ? 1 : -1;
}

static void json_string(char* out, size_t size, const char* in) {
    size_t o = 0;
    for (; *in && o + 7 < size; in++) {
        const unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        }
        else if (c < 0x20) {
            o += (size_t)snprintf(out + o, size - o, "\\u%04x", c);
        }
        else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

static bool usable_shell(const char* path) {
    if (!path || path[0] != '/' || access(path, X_OK) != 0) return false;
    const char* base = strrchr(path, '/') + 1;
    return strcmp(base, "nologin") != 0 && strcmp(base, "false") != 0;
}

static void usage(void) {
    fprintf(stderr,
        "usage: koios-shell [--user NAME] [--shell PATH]\n"
        "\n"
        "A login shell on a terminal, for a Koios console session. Standard input\n"
        "and output are the session's stream; koios-agent or a socket unit starts it.\n"
        "  --user NAME   run the shell as this user (needs root)\n"
        "  --shell PATH  the shell to run instead of the user's own\n");
}

int main(int argc, char** argv) {
    const char* want_user = NULL;
    const char* want_shell = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--user") && i + 1 < argc) want_user = argv[++i];
        else if (!strcmp(argv[i], "--shell") && i + 1 < argc) want_shell = argv[++i];
        else {
            usage();
            return strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 ? 0 : 2;
        }
    }
    if (isatty(s_in)) {
        usage();
        return 2;
    }

    // Whatever the program that started this one had open is not the shell's.
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) max_fd = 65536;
    for (int fd = 3; fd < (int)max_fd; fd++) close(fd);

    const struct passwd* pw = want_user ? getpwnam(want_user) : getpwuid(getuid());
    if (!pw) {
        say("no such user: %s", want_user ? want_user : "(the current one)");
        return 1;
    }
    const bool switch_user = pw->pw_uid != getuid();
    if (switch_user && geteuid() != 0) {
        say("not started as root: cannot run a shell as %s", pw->pw_name);
        return 1;
    }
    char user[64], home[256], shell[256];
    snprintf(user, sizeof(user), "%s", pw->pw_name);
    snprintf(home, sizeof(home), "%s", pw->pw_dir && pw->pw_dir[0] ? pw->pw_dir : "/");
    snprintf(shell, sizeof(shell), "%s",
        want_shell ? want_shell : usable_shell(pw->pw_shell) ? pw->pw_shell : "/bin/sh");
    const uid_t uid = pw->pw_uid;
    const gid_t gid = pw->pw_gid;
    if (access(shell, X_OK) != 0) {
        say("cannot run %s: %s", shell, strerror(errno));
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_stop };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = on_child;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    // The terminal. The slave is opened here, before the shell exists, and the
    // shell inherits it: there is then no moment at which nobody holds it, which
    // is when the master would report a hang-up.
    s_master = posix_openpt(O_RDWR | O_NOCTTY);
    const char* slave_name = NULL;
    if (s_master < 0 || grantpt(s_master) != 0 || unlockpt(s_master) != 0 || !(slave_name = ptsname(s_master))) {
        say("no terminal: %s", strerror(errno));
        return 1;
    }
    const int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        say("cannot open %s: %s", slave_name, strerror(errno));
        return 1;
    }
    if (switch_user && fchown(slave, uid, (gid_t)-1) != 0) {
        say("cannot give the terminal to %s: %s", user, strerror(errno));
    }
    struct winsize ws = { .ws_col = 80, .ws_row = 24 };
    ioctl(s_master, TIOCSWINSZ, &ws);
    fcntl(s_master, F_SETFL, fcntl(s_master, F_GETFL, 0) | O_NONBLOCK);
    fcntl(s_master, F_SETFD, FD_CLOEXEC);

    char host[128] = "";
    gethostname(host, sizeof(host) - 1);
    char j_user[160], j_host[300], j_shell[600], hello[1200];
    json_string(j_user, sizeof(j_user), user);
    json_string(j_host, sizeof(j_host), host);
    json_string(j_shell, sizeof(j_shell), shell);
    const int hello_len = snprintf(hello, sizeof(hello),
        "{\"v\":1,\"user\":\"%s\",\"host\":\"%s\",\"shell\":\"%s\"}", j_user, j_host, j_shell);
    if (!send_frame(F_HELLO, hello, (uint32_t)hello_len)) return 0;  // nobody there

    // The terminal's size comes first if the other end sends it at once: wait a
    // moment for it, so that the shell starts at the right size.
    struct pollfd first = { .fd = s_in, .events = POLLIN };
    if (poll(&first, 1, FIRST_FRAME_MS) == 1 && read_stream() < 0) return 0;

    const pid_t child = fork();
    if (child < 0) {
        say("cannot start the shell: %s", strerror(errno));
        return 1;
    }
    if (child == 0) {
        close(s_master);
        setsid();
        ioctl(slave, TIOCSCTTY, 0);
        dup2(slave, 0);
        dup2(slave, 1);
        dup2(slave, 2);
        if (slave > 2) close(slave);
        if (switch_user && (initgroups(user, gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0)) {
            fprintf(stderr, "koios-shell: cannot become %s: %s\r\n", user, strerror(errno));
            _exit(126);
        }
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);

        // A login's environment and nothing else of this program's.
        const char* lang = getenv("LANG");
        const char* lc_all = getenv("LC_ALL");
        const char* path = getenv("PATH");
        const char* runtime = switch_user ? NULL : getenv("XDG_RUNTIME_DIR");
        char e_home[300], e_user[100], e_logname[100], e_shell[300], e_path[1100], e_lang[100], e_lc[100], e_run[300];
        char* env[12];
        int n = 0;
        env[n++] = "TERM=xterm-256color";
        env[n++] = "KOIOS_CONSOLE=1";
        snprintf(e_home, sizeof(e_home), "HOME=%s", home);
        env[n++] = e_home;
        snprintf(e_user, sizeof(e_user), "USER=%s", user);
        env[n++] = e_user;
        snprintf(e_logname, sizeof(e_logname), "LOGNAME=%s", user);
        env[n++] = e_logname;
        snprintf(e_shell, sizeof(e_shell), "SHELL=%s", shell);
        env[n++] = e_shell;
        snprintf(e_path, sizeof(e_path), "PATH=%s",
            path && path[0] ? path : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        env[n++] = e_path;
        if (lang && lang[0] && strlen(lang) < 80) {
            snprintf(e_lang, sizeof(e_lang), "LANG=%s", lang);
            env[n++] = e_lang;
        }
        if (lc_all && lc_all[0] && strlen(lc_all) < 80) {
            snprintf(e_lc, sizeof(e_lc), "LC_ALL=%s", lc_all);
            env[n++] = e_lc;
        }
        if (runtime && runtime[0] && strlen(runtime) < 250) {
            snprintf(e_run, sizeof(e_run), "XDG_RUNTIME_DIR=%s", runtime);
            env[n++] = e_run;
        }
        env[n] = NULL;

        if (chdir(home) != 0 && chdir("/") != 0) _exit(126);
        // "-bash": a login shell reads the profile.
        const char* base = strrchr(shell, '/');
        char arg0[260];
        snprintf(arg0, sizeof(arg0), "-%s", base ? base + 1 : shell);
        char* const args[] = { arg0, NULL };
        execve(shell, args, env);
        fprintf(stderr, "koios-shell: cannot run %s: %s\r\n", shell, strerror(errno));
        _exit(127);
    }
    close(slave);
    say("shell %s for %s started (pid %d)", shell, user, (int)child);

    bool stream_open = true;
    int status = 0;
    bool exited = false;
    struct pollfd fds[2] = { { .fd = s_in, .events = POLLIN }, { .fd = s_master, .events = POLLIN } };
    while (stream_open && !s_stop) {
        if (waitpid(child, &status, WNOHANG) == child) {
            exited = true;
            break;
        }
        fds[0].revents = fds[1].revents = 0;
        if (poll(fds, 2, 1000) < 0) continue;  // a signal: look again
        if (fds[1].revents && drain_terminal() < 0) {
            // Every process has closed the terminal, which is the shell ending
            // (give its exit a moment to arrive), or the stream broke.
            const int64_t until = now_ms() + 500;
            while (!exited && now_ms() < until) {
                if (waitpid(child, &status, WNOHANG) == child) exited = true;
                else usleep(20 * 1000);
            }
            break;
        }
        if (fds[0].revents && read_stream() < 0) stream_open = false;
    }

    if (exited) {
        // What the shell printed last, then how it ended.
        for (int i = 0; i < 64 && drain_terminal() > 0; i++) {}
        const int code = WIFEXITED(status) ? WEXITSTATUS(status) : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255;
        const uint8_t payload[4] = { (uint8_t)((uint32_t)code >> 24), (uint8_t)(code >> 16), (uint8_t)(code >> 8), (uint8_t)code };
        send_frame(F_EXIT, payload, sizeof(payload));
        say("shell for %s ended with status %d", user, code);
    }

    // Hang up: the shell (if it is still there) and whatever it left behind on
    // the terminal get SIGHUP. Under a service manager the unit's stop takes
    // care of what ignores it.
    close(s_master);
    kill(-child, SIGHUP);
    if (!exited) {
        const int64_t until = now_ms() + HANGUP_WAIT_MS;
        while (waitpid(child, &status, WNOHANG) != child) {
            if (now_ms() >= until) {
                kill(-child, SIGKILL);
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
                break;
            }
            usleep(20 * 1000);
        }
        say("shell for %s ended with the session", user);
    }
    return 0;
}
