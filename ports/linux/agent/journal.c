// Follow the systemd journal and push every entry into the SDK's log ring.
//
// journalctl does the reading (`--follow --output=json`): no dependency on
// libsystemd, and a system without a journal simply has no follower. The
// cursor of the last entry read is kept in the state directory, so a restart
// continues where it stopped instead of shipping the history again.

#include "journal.h"

#include "koios/linux.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_logstore.h"

#include <cJSON.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

static const char* TAG = "journal";

#define CURSOR_SAVE_INTERVAL_S 10
#define RESTART_DELAY_S        5

static struct {
    int priority;
    int backlog;
    char cursor_path[512];
    char cursor[256];
    pid_t child;
    atomic_bool stop;
    pthread_t thread;
    bool started;
    pid_t self;
} s;

static int level_of(int priority) {
    if (priority <= 3) return KOIOS_LOG_ERROR;
    if (priority == 4) return KOIOS_LOG_WARN;
    if (priority <= 6) return KOIOS_LOG_INFO;
    return KOIOS_LOG_DEBUG;
}

static void load_cursor(void) {
    s.cursor[0] = '\0';
    FILE* f = fopen(s.cursor_path, "r");
    if (!f) return;
    if (fgets(s.cursor, sizeof(s.cursor), f)) s.cursor[strcspn(s.cursor, "\r\n")] = '\0';
    fclose(f);
}

static void save_cursor(void) {
    if (!s.cursor[0] || !s.cursor_path[0]) return;
    char tmp[540];
    snprintf(tmp, sizeof(tmp), "%s.tmp", s.cursor_path);
    FILE* f = fopen(tmp, "w");
    if (!f) return;
    const bool ok = fputs(s.cursor, f) >= 0;
    if (fclose(f) == 0 && ok) rename(tmp, s.cursor_path);
    else remove(tmp);
}

// One line of `journalctl -o json`.
static void handle_entry(const char* line) {
    cJSON* e = cJSON_Parse(line);
    if (!e) return;

    const char* cursor = cJSON_GetStringValue(cJSON_GetObjectItem(e, "__CURSOR"));
    if (cursor && strlen(cursor) < sizeof(s.cursor)) snprintf(s.cursor, sizeof(s.cursor), "%s", cursor);

    // Our own lines reach the ring directly; taking them from the journal
    // too would ship each one twice.
    const char* pid = cJSON_GetStringValue(cJSON_GetObjectItem(e, "_PID"));
    const bool own = pid && atoi(pid) == (int)s.self;

    // MESSAGE is a string, or an array of byte values when it is not UTF-8.
    const char* msg = cJSON_GetStringValue(cJSON_GetObjectItem(e, "MESSAGE"));
    if (!own && msg && msg[0]) {
        const char* prio = cJSON_GetStringValue(cJSON_GetObjectItem(e, "PRIORITY"));
        const int priority = (prio && prio[0] >= '0' && prio[0] <= '7') ? prio[0] - '0' : 6;

        const char* tag = cJSON_GetStringValue(cJSON_GetObjectItem(e, "SYSLOG_IDENTIFIER"));
        if (!tag || !tag[0]) tag = cJSON_GetStringValue(cJSON_GetObjectItem(e, "_COMM"));
        if (!tag || !tag[0]) tag = cJSON_GetStringValue(cJSON_GetObjectItem(e, "_SYSTEMD_UNIT"));
        if (!tag || !tag[0]) tag = "journal";

        // Microseconds since the epoch, as a decimal string.
        int64_t ts_ms = 0;
        const char* rt = cJSON_GetStringValue(cJSON_GetObjectItem(e, "__REALTIME_TIMESTAMP"));
        if (rt) ts_ms = strtoll(rt, NULL, 10) / 1000;

        koios_linux_log_push(level_of(priority), tag, msg, ts_ms);
    }
    cJSON_Delete(e);
}

static pid_t spawn_journalctl(int* out_fd) {
    int fds[2];
    if (pipe(fds) != 0) return -1;

    char prio[8], lines[16], after[300];
    snprintf(prio, sizeof(prio), "%d", s.priority);
    snprintf(lines, sizeof(lines), "%d", s.backlog);
    char* argv[12];
    int argc = 0;
    argv[argc++] = "journalctl";
    argv[argc++] = "--follow";
    argv[argc++] = "--output=json";
    argv[argc++] = "--no-pager";
    argv[argc++] = "--priority";
    argv[argc++] = prio;
    if (s.cursor[0]) {
        snprintf(after, sizeof(after), "--after-cursor=%s", s.cursor);
        argv[argc++] = after;
    }
    else {
        argv[argc++] = "--lines";
        argv[argc++] = lines;
    }
    argv[argc] = NULL;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[0]);
    posix_spawn_file_actions_addclose(&actions, fds[1]);
    pid_t pid = -1;
    const int rc = posix_spawnp(&pid, "journalctl", &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        errno = rc;
        return -1;
    }
    *out_fd = fds[0];
    return pid;
}

static void* follow_thread(void* arg) {
    (void)arg;
    bool warned = false;
    while (!atomic_load(&s.stop)) {
        int fd = -1;
        const pid_t pid = spawn_journalctl(&fd);
        if (pid < 0) {
            if (!warned) KP_LOGW(TAG, "cannot run journalctl (%s): the journal is not shipped", strerror(errno));
            warned = true;
            return NULL;
        }
        s.child = pid;

        FILE* in = fdopen(fd, "r");
        char* line = NULL;
        size_t cap = 0;
        time_t last_save = time(NULL);
        while (in && getline(&line, &cap, in) > 0) {
            handle_entry(line);
            const time_t now = time(NULL);
            if (now - last_save >= CURSOR_SAVE_INTERVAL_S) {
                save_cursor();
                last_save = now;
            }
        }
        free(line);
        if (in) fclose(in);
        else close(fd);
        save_cursor();

        int status = 0;
        waitpid(pid, &status, 0);
        s.child = 0;
        if (atomic_load(&s.stop)) break;

        // A cursor the journal no longer has (rotated away) makes journalctl
        // exit at once: start from the present instead.
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0 && s.cursor[0]) {
            KP_LOGW(TAG, "journalctl exited with status %d; continuing from the newest entries", WEXITSTATUS(status));
            s.cursor[0] = '\0';
            s.backlog = 0;
        }
        for (int i = 0; i < RESTART_DELAY_S && !atomic_load(&s.stop); i++) sleep(1);
    }
    return NULL;
}

void agent_journal_start(const char* state_dir, int priority, int backlog) {
    if (s.started) return;
    s.priority = priority;
    s.backlog = backlog;
    s.self = getpid();
    if (state_dir) {
        snprintf(s.cursor_path, sizeof(s.cursor_path), "%s/journal.cursor", state_dir);
        load_cursor();
    }
    s.started = pthread_create(&s.thread, NULL, follow_thread, NULL) == 0;
}

void agent_journal_stop(void) {
    if (!s.started) return;
    atomic_store(&s.stop, true);
    if (s.child > 0) kill(s.child, SIGTERM);
    pthread_join(s.thread, NULL);
    s.started = false;
}
