// koios-agent: makes a Linux machine a Koios device.
//
// It holds the cloudlink session, reports what the machine runs, ships its
// journal, reports system metrics, and (when the system provides an
// installer) takes updates. Everything it does is set in one configuration
// file; docs/linux.md describes it.

#include "config.h"
#include "journal.h"

#include "koios/cloudlink.h"
#include "koios/console.h"
#include "koios/linux.h"
#include "koios/logship.h"
#include "koios/metrics.h"
#include "koios/ota.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_os.h"

#include <cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifndef KOIOS_AGENT_VERSION
#define KOIOS_AGENT_VERSION "0.0.0"
#endif

static const char* TAG = "agent";

static agent_config_t s_cfg;
static atomic_bool s_stop;
static atomic_bool s_report_facts;
static time_t s_facts_mtime;

//------------------------------------------------------------------------------
// systemd notification (sd_notify without libsystemd)
//------------------------------------------------------------------------------

static void sd_notify_line(const char* state) {
    const char* path = getenv("NOTIFY_SOCKET");
    if (!path || !path[0]) return;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(addr.sun_path)) return;
    strcpy(addr.sun_path, path);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path));
    if (addr.sun_path[0] == '@') addr.sun_path[0] = '\0';  // abstract socket
    const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return;
    sendto(fd, state, strlen(state), 0, (struct sockaddr*)&addr, len);
    close(fd);
}

//------------------------------------------------------------------------------
// API key (api_key mode)
//------------------------------------------------------------------------------

static char* read_api_key(void) {
    const char* env = getenv("KOIOS_API_KEY");
    if (env && env[0]) return strdup(env);
    FILE* f = fopen(s_cfg.api_key_file, "r");
    if (!f) return NULL;
    char line[256] = "";
    const bool ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    if (!ok) return NULL;
    line[strcspn(line, "\r\n \t")] = '\0';
    return line[0] ? strdup(line) : NULL;
}

// The gateway minted this device's own key (the configured one was a fleet's
// provisioning key). It is sent once: keep it, for this device only.
static void on_api_key_issued(const char* api_key) {
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", s_cfg.api_key_file);
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        KP_LOGE(TAG, "cannot store the device key in %s: %s", s_cfg.api_key_file, strerror(errno));
        return;
    }
    const size_t n = strlen(api_key);
    const bool ok = write(fd, api_key, n) == (ssize_t)n && write(fd, "\n", 1) == 1;
    if (close(fd) == 0 && ok && rename(tmp, s_cfg.api_key_file) == 0) {
        KP_LOGI(TAG, "device key issued and stored");
    }
    else {
        remove(tmp);
        KP_LOGE(TAG, "cannot store the device key in %s", s_cfg.api_key_file);
    }
}

//------------------------------------------------------------------------------
// What the machine reports about itself (twin reported state)
//------------------------------------------------------------------------------

// {"type":"twin.report","mode":"patch","state":{"sys":{...}, <facts file>}}
static void report_facts(void) {
    cJSON* root = cJSON_CreateObject();
    cJSON* state = NULL;
    if (s_cfg.facts_file) {
        FILE* f = fopen(s_cfg.facts_file, "r");
        if (f) {
            char buf[8192];
            const size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            buf[n] = '\0';
            state = cJSON_Parse(buf);
            if (state && !cJSON_IsObject(state)) {
                cJSON_Delete(state);
                state = NULL;
            }
            if (!state) KP_LOGW(TAG, "%s is not a JSON object, ignoring it", s_cfg.facts_file);
        }
    }
    if (!state) state = cJSON_CreateObject();
    if (!root || !state) {
        cJSON_Delete(root);
        cJSON_Delete(state);
        return;
    }
    cJSON_AddStringToObject(root, "type", "twin.report");
    cJSON_AddStringToObject(root, "mode", "patch");

    // "sys" is the agent's; a facts file cannot replace it.
    cJSON_DeleteItemFromObject(state, "sys");
    cJSON_DeleteItemFromObject(state, "fw");
    cJSON* sys = cJSON_AddObjectToObject(state, "sys");
    char host[128] = "";
    if (gethostname(host, sizeof(host) - 1) == 0 && host[0]) cJSON_AddStringToObject(sys, "hostname", host);
    struct utsname u;
    if (uname(&u) == 0) {
        cJSON_AddStringToObject(sys, "kernel", u.release);
        cJSON_AddStringToObject(sys, "arch", u.machine);
    }
    char* os = agent_os_release_value(s_cfg.os_release, "PRETTY_NAME");
    if (os) cJSON_AddStringToObject(sys, "os", os);
    free(os);
    cJSON_AddStringToObject(sys, "agent", KOIOS_AGENT_VERSION);
    cJSON_AddItemToObject(root, "state", state);

    char* json = cJSON_PrintUnformatted(root);
    if (json) {
        if (!koios_cloudlink_send_text(json)) KP_LOGW(TAG, "could not queue the system report");
        cJSON_free(json);
    }
    cJSON_Delete(root);
}

static time_t facts_mtime(void) {
    struct stat st;
    if (!s_cfg.facts_file || stat(s_cfg.facts_file, &st) != 0) return 0;
    return st.st_mtime;
}

//------------------------------------------------------------------------------
// Cloudlink callbacks (the WebSocket thread: never block here)
//------------------------------------------------------------------------------

static void on_state_change(koios_cloud_state_t state) {
    switch (state) {
    case KOIOS_CLOUD_STATE_WAITING:
        KP_LOGI(TAG, "waiting for the network or the identity");
        sd_notify_line("STATUS=Waiting for the network or the identity");
        break;
    case KOIOS_CLOUD_STATE_CONNECTING:
        sd_notify_line("STATUS=Connecting to Koios");
        break;
    case KOIOS_CLOUD_STATE_READY: {
        char id[48] = "";
        koios_cloudlink_get_device_id(id, sizeof(id));
        KP_LOGI(TAG, "session ready (device %s)", id[0] ? id : "?");
        char status[96];
        snprintf(status, sizeof(status), "STATUS=Connected to Koios as %s", id[0] ? id : "?");
        sd_notify_line(status);
        break;
    }
    }
}

static void on_session_ready(void) {
    atomic_store(&s_report_facts, true);  // the main loop sends it
}

static void on_message(const uint8_t* data, size_t len) {
    (void)data;
    KP_LOGD(TAG, "ignoring a binary message of %u bytes (the agent has no application protocol)", (unsigned)len);
}

static void on_control(const char* json, size_t len) {
    KP_LOGD(TAG, "unhandled control frame: %.*s", (int)(len > 120 ? 120 : len), json);
}

//------------------------------------------------------------------------------
// Main
//------------------------------------------------------------------------------

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&s_stop, true);
}

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s [-c FILE] [-v] [--check]\n"
        "  -c FILE   configuration (default /etc/koios/agent.conf)\n"
        "  -v        debug logging\n"
        "  --check   read the configuration, say what would run, and exit\n"
        "  --version\n", argv0);
}

static void print_plan(void) {
    printf("cloud:     %s (%s)\n", s_cfg.url, s_cfg.mtls ? "mTLS" : "API key");
    if (s_cfg.mtls) {
        printf("identity:  certificate %s\n", s_cfg.cert);
        if (s_cfg.extra_chain) printf("           plus the intermediates in %s\n", s_cfg.extra_chain);
        printf("           key %s\n", strncmp(s_cfg.key, "pkcs11:", 7) == 0 ? "behind PKCS#11" : "in a file");
        if (s_cfg.ready_file) printf("           waits for %s\n", s_cfg.ready_file);
    }
    printf("device:    class %s, project %s, version %s%s%s\n",
        s_cfg.device_class ? s_cfg.device_class : "(from uname)",
        s_cfg.project ? s_cfg.project : "(none)", s_cfg.version ? s_cfg.version : "(none)",
        s_cfg.variant ? ", variant " : "", s_cfg.variant ? s_cfg.variant : "");
    printf("logs:      %s%s\n", s_cfg.logs ? "shipped" : "off",
        s_cfg.logs && s_cfg.journal ? ", with the journal" : "");
    if (s_cfg.metrics) printf("metrics:   every %u s\n", (unsigned)s_cfg.metrics_interval_s);
    else printf("metrics:   off\n");
    if (s_cfg.ota) printf("updates:   installed by: %s\n", s_cfg.ota_apply_cmd);
    else printf("updates:   not taken from Koios\n");
    if (s_cfg.console && s_cfg.console_target_count) {
        printf("console:   ");
        for (size_t i = 0; i < s_cfg.console_target_count; i++) {
            printf("%s%s -> %s", i ? ", " : "", s_cfg.console_targets[i].name, s_cfg.console_targets[i].address);
        }
        printf("\n");
    }
    else {
        printf("console:   off\n");
    }
}

int main(int argc, char** argv) {
    const char* conf = "/etc/koios/agent.conf";
    bool verbose = false, check = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) conf = argv[++i];
        else if (!strcmp(argv[i], "-v")) verbose = true;
        else if (!strcmp(argv[i], "--check")) check = true;
        else if (!strcmp(argv[i], "--version")) {
            printf("koios-agent %s\n", KOIOS_AGENT_VERSION);
            return 0;
        }
        else {
            usage(argv[0]);
            return 2;
        }
    }

    char err[400];
    if (agent_config_load(conf, &s_cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "koios-agent: %s\n", err);
        return 2;
    }

    // What the machine is, from os-release unless the configuration says so.
    if (!s_cfg.project) s_cfg.project = agent_os_release_value(s_cfg.os_release, "ID");
    if (!s_cfg.version) s_cfg.version = agent_os_release_value(s_cfg.os_release, "VERSION_ID");
    if (!s_cfg.variant) s_cfg.variant = agent_os_release_value(s_cfg.os_release, "VARIANT_ID");

    if (check) {
        print_plan();
        return 0;
    }

    // A peer that goes away must not kill the process on the next write.
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    const koios_linux_config_t port = {
        .cert_file = s_cfg.cert,
        .extra_chain_file = s_cfg.extra_chain,
        .key = s_cfg.key,
        .identity_ready_file = s_cfg.ready_file,
        .ca_file = s_cfg.ca_file,
        .device_class = s_cfg.device_class,
        .project = s_cfg.project,
        .version = s_cfg.version,
        .state_dir = s_cfg.state_dir,
        .runtime_dir = s_cfg.runtime_dir,
        .log_ring_bytes = s_cfg.ring_bytes,
        .log_level = verbose ? 3 : 2,
        .capture_own_logs = s_cfg.logs,
        .storage_path = s_cfg.storage_path,
        .net_iface = s_cfg.net_iface,
        .ota_staging_dir = s_cfg.ota_staging_dir,
        .ota_apply_cmd = s_cfg.ota ? s_cfg.ota_apply_cmd : NULL,
        .ota_restart_cmd = s_cfg.ota ? s_cfg.ota_restart_cmd : NULL,
    };
    if (koios_linux_init(&port) != 0) {
        fprintf(stderr, "koios-agent: cannot create %s or %s\n",
            s_cfg.state_dir ? s_cfg.state_dir : "(no state dir)",
            s_cfg.runtime_dir ? s_cfg.runtime_dir : "(no runtime dir)");
        return 1;
    }
    KP_LOGI(TAG, "koios-agent %s starting (%s)", KOIOS_AGENT_VERSION, s_cfg.url);

    char* api_key = NULL;
    if (!s_cfg.mtls) {
        api_key = read_api_key();
        if (!api_key) {
            KP_LOGE(TAG, "no API key in %s", s_cfg.api_key_file);
            return 1;
        }
    }

    // Capture starts before the link so that the first lines are not lost.
    if (s_cfg.logs) koios_logship_init(NULL);

    const koios_cloudlink_config_t link = {
        .url = s_cfg.url,
        .auth_mode = s_cfg.mtls ? KOIOS_CLOUD_AUTH_MTLS : KOIOS_CLOUD_AUTH_API_KEY,
        .api_key = api_key,
        .variant = s_cfg.variant,
        .max_msg_size = 64 * 1024,
        .queue_depth = 32,
        .on_state_change = on_state_change,
        .on_session_ready = on_session_ready,
        .on_message = on_message,
        .on_control = on_control,
        .on_api_key_issued = s_cfg.mtls ? NULL : on_api_key_issued,
        // No renewal handlers: the certificate belongs to whoever issued it.
        // A `cert.renew_required` from the gateway is declined.
    };
    koios_cloudlink_init(&link);
    free(api_key);

    if (s_cfg.ota) {
        const koios_ota_config_t ota = { .endpoint_url = s_cfg.ota_endpoint };
        koios_ota_init(&ota);
    }
    if (s_cfg.metrics) {
        const koios_metrics_config_t metrics = { .interval_s = s_cfg.metrics_interval_s };
        koios_metrics_init(&metrics);
    }
    if (s_cfg.console) {
        koios_console_target_t targets[AGENT_MAX_CONSOLE_TARGETS];
        for (size_t i = 0; i < s_cfg.console_target_count; i++) {
            targets[i].name = s_cfg.console_targets[i].name;
            targets[i].address = s_cfg.console_targets[i].address;
        }
        const koios_console_config_t console = {
            .url = s_cfg.url,
            .mtls = s_cfg.mtls,
            .targets = targets,
            .target_count = s_cfg.console_target_count,
        };
        koios_console_init(&console);
    }
    if (s_cfg.logs && s_cfg.journal) {
        agent_journal_start(s_cfg.state_dir, s_cfg.journal_priority, s_cfg.journal_backlog);
    }

    sd_notify_line("READY=1");

    // The main thread has little to do: send the system report when a session
    // starts or the facts file changes, feed the watchdog, wait for a signal.
    const char* wd = getenv("WATCHDOG_USEC");
    const long long wd_us = wd ? atoll(wd) : 0;
    int64_t next_wd = kp_monotonic_us();
    int64_t next_facts_check = kp_monotonic_us();
    while (!atomic_load(&s_stop)) {
        const int64_t now = kp_monotonic_us();
        if (wd_us > 0 && now >= next_wd) {
            sd_notify_line("WATCHDOG=1");
            next_wd = now + wd_us / 2;
        }
        if (now >= next_facts_check) {
            next_facts_check = now + 30LL * 1000000;
            const time_t mtime = facts_mtime();
            if (mtime != s_facts_mtime) {
                s_facts_mtime = mtime;
                atomic_store(&s_report_facts, true);
            }
        }
        if (koios_cloudlink_is_ready() && atomic_exchange(&s_report_facts, false)) report_facts();
        kp_delay_ms(500);
    }

    KP_LOGI(TAG, "stopping");
    sd_notify_line("STOPPING=1");
    agent_journal_stop();
    koios_logship_flush();
    kp_delay_ms(300);  // let the last frames leave
    koios_cloudlink_deinit();
    return 0;
}
