// Console session policy (portable): whether a session the gateway asks for is
// taken, and how many at a time. Carrying the stream is the port's
// (kp_console).
//
// Compiled to a refusal unless CONFIG_KOIOS_SDK_CONSOLE_ENABLE is defined, so
// that an operator who asks a device without console is told at once.

#include "koios/console.h"

#include "koios/cloudlink.h"
#include "koios/port/kp_log.h"
#include "koios/port/kp_os.h"

#include <cJSON.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static const char* TAG = "koios_console";

// A session id is a UUID; it becomes part of a URL.
static bool valid_session_id(const char* id) {
    if (!id || strlen(id) != 36) return false;
    for (const char* p = id; *p; p++) {
        const char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-')) return false;
    }
    return true;
}

static void refuse(const char* session, const char* reason) {
    char frame[256];
    snprintf(frame, sizeof(frame),
        "{\"type\":\"console.status\",\"session\":\"%s\",\"state\":\"refused\",\"reason\":\"%s\"}",
        session, reason);
    koios_cloudlink_send_text(frame);
    KP_LOGW(TAG, "Console session %s refused: %s", session, reason);
}

#if defined(CONFIG_KOIOS_SDK_CONSOLE_ENABLE)

#include "koios/port/kp_console.h"

#define DEFAULT_MAX_SESSIONS 4
#define MAX_TARGETS          8
#define TARGET_NAME_LEN      24
#define TARGET_ADDRESS_LEN   256
#define URL_LEN              320
#define BY_LEN               80
#define TASK_STACK_BYTES     8192
#define TASK_PRIORITY        4

typedef struct {
    char name[TARGET_NAME_LEN];
    char address[TARGET_ADDRESS_LEN];
} target_t;

static struct {
    bool running;
    char url[200];
    bool mtls;
    target_t targets[MAX_TARGETS];
    size_t target_count;
    int max_sessions;
    atomic_int active;
} s;

typedef struct {
    char session_id[40];
    char url[URL_LEN];
    char target_name[TARGET_NAME_LEN];
    char target_address[TARGET_ADDRESS_LEN];
    char by[BY_LEN];  // who opened it, as the gateway says; for this device's own log
    char* token;  // kp_malloc'd
} job_t;

static void session_task(void* arg) {
    job_t* job = arg;
    const kp_console_session_t session = {
        .session_id = job->session_id,
        .url = job->url,
        .bearer = job->token,
        .mtls = s.mtls,
        .target_name = job->target_name,
        .target_address = job->target_address,
    };
    KP_LOGI(TAG, "Console session %s to '%s' opening for %s", job->session_id, job->target_name,
        job->by[0] ? job->by : "(not named)");
    const int rc = kp_console_run(&session);
    if (rc == 0) KP_LOGI(TAG, "Console session %s ended", job->session_id);
    else KP_LOGW(TAG, "Console session %s did not start", job->session_id);
    atomic_fetch_sub(&s.active, 1);
    kp_free(job->token);
    kp_free(job);
}

void koios_console_init(const koios_console_config_t* config) {
    if (s.running || !config || !config->url) return;
    snprintf(s.url, sizeof(s.url), "%s", config->url);
    for (size_t n = strlen(s.url); n > 0 && s.url[n - 1] == '/'; n--) s.url[n - 1] = '\0';
    s.mtls = config->mtls;
    s.max_sessions = config->max_sessions ? config->max_sessions : DEFAULT_MAX_SESSIONS;
    s.target_count = 0;
    for (size_t i = 0; i < config->target_count && s.target_count < MAX_TARGETS; i++) {
        const koios_console_target_t* t = &config->targets[i];
        if (!t->name || !t->address || !t->name[0] || !t->address[0]) continue;
        if (strlen(t->name) >= TARGET_NAME_LEN || strlen(t->address) >= TARGET_ADDRESS_LEN) continue;
        snprintf(s.targets[s.target_count].name, TARGET_NAME_LEN, "%s", t->name);
        snprintf(s.targets[s.target_count].address, TARGET_ADDRESS_LEN, "%s", t->address);
        s.target_count++;
    }
    if (s.target_count == 0) {
        KP_LOGW(TAG, "Console enabled without a target: every session will be refused");
    }
    s.running = true;
    KP_LOGI(TAG, "Console sessions allowed to %u target(s), %d at a time",
        (unsigned)s.target_count, s.max_sessions);
}

void koios_console_on_open(const struct cJSON* frame) {
    const char* session = cJSON_GetStringValue(cJSON_GetObjectItem(frame, "session"));
    const char* target = cJSON_GetStringValue(cJSON_GetObjectItem(frame, "target"));
    if (!valid_session_id(session)) {
        KP_LOGW(TAG, "console.open without a usable session id, ignoring");
        return;
    }
    if (!s.running) {
        refuse(session, "console is off on this device");
        return;
    }

    // The cloud names a target; only the device's own configuration says what
    // address that is.
    const target_t* found = NULL;
    for (size_t i = 0; target && i < s.target_count; i++) {
        if (strcmp(s.targets[i].name, target) == 0) found = &s.targets[i];
    }
    if (!found) {
        refuse(session, "no such target on this device");
        return;
    }

    if (atomic_fetch_add(&s.active, 1) >= s.max_sessions) {
        atomic_fetch_sub(&s.active, 1);
        refuse(session, "too many console sessions");
        return;
    }

    job_t* job = kp_calloc(1, sizeof(*job));
    char* token = koios_cloudlink_get_token_copy();
    if (!job || !token) {
        kp_free(job);
        kp_free(token);
        atomic_fetch_sub(&s.active, 1);
        refuse(session, "device is not ready");
        return;
    }
    job->token = token;
    snprintf(job->session_id, sizeof(job->session_id), "%s", session);
    snprintf(job->target_name, sizeof(job->target_name), "%s", found->name);
    snprintf(job->target_address, sizeof(job->target_address), "%s", found->address);
    // The name goes into a log line: printable characters only.
    const char* by = cJSON_GetStringValue(cJSON_GetObjectItem(frame, "by"));
    size_t n = 0;
    for (; by && *by && n + 1 < sizeof(job->by); by++) {
        if (*by > 0x20 && *by < 0x7f) job->by[n++] = *by;
    }
    job->by[n] = '\0';
    snprintf(job->url, sizeof(job->url), "%s/v1/console/sessions/%s/device", s.url, session);

    if (!kp_task_spawn("koios_console", session_task, job, TASK_STACK_BYTES, TASK_PRIORITY)) {
        kp_free(job->token);
        kp_free(job);
        atomic_fetch_sub(&s.active, 1);
        refuse(session, "device is not ready");
    }
}

#else  // !CONFIG_KOIOS_SDK_CONSOLE_ENABLE

void koios_console_init(const koios_console_config_t* config) {
    (void)config;
    KP_LOGD(TAG, "disabled (CONFIG_KOIOS_SDK_CONSOLE_ENABLE not set)");
}

void koios_console_on_open(const struct cJSON* frame) {
    const char* session = cJSON_GetStringValue(cJSON_GetObjectItem(frame, "session"));
    if (valid_session_id(session)) refuse(session, "this firmware has no console");
}

#endif
