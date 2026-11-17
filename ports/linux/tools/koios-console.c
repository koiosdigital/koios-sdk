// koios-console: the operator's end of a console session.
//
//   koios-console attach <operator-url> <ticket>
//
// Connects to the session the Koios console opened and joins it to stdin and
// stdout. It is made to be ssh's ProxyCommand:
//
//   ssh -o ProxyCommand='koios-console attach <operator-url> <ticket>' user@box
//
// ssh then talks to the device's own sshd through the gateway. The gateway
// relays the bytes; it sees an SSH connection, not what is in it, and the
// usual host-key check tells you the far end is the box you meant.
//
// The ticket is the one the console showed for this session: it works once
// and for a few minutes. It can also be given in KOIOS_CONSOLE_TICKET instead
// of on the command line.

#include "koios/linux.h"
#include "../console_stream.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr,
        "usage: koios-console attach <operator-url> [<ticket>] [--ca-file FILE]\n"
        "\n"
        "  Joins a console session to stdin and stdout. Use it as ssh's ProxyCommand:\n"
        "    ssh -o ProxyCommand='koios-console attach <operator-url> <ticket>' user@device\n"
        "  The ticket may be given in KOIOS_CONSOLE_TICKET instead.\n");
}

int main(int argc, char** argv) {
    const char* url = NULL;
    const char* ticket = getenv("KOIOS_CONSOLE_TICKET");
    const char* ca_file = NULL;
    if (argc < 3 || strcmp(argv[1], "attach") != 0) {
        usage();
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--ca-file") == 0 && i + 1 < argc) ca_file = argv[++i];
        else if (!url) url = argv[i];
        else ticket = argv[i];
    }
    if (!url || !ticket || !ticket[0]) {
        usage();
        return 2;
    }
    if (strncmp(url, "wss://", 6) != 0 && strncmp(url, "ws://", 5) != 0) {
        fprintf(stderr, "koios-console: the session URL must start with wss://\n");
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    // Quiet unless something is wrong: ssh shows this program's stderr.
    const koios_linux_config_t port = { .ca_file = ca_file, .log_level = 0 };
    koios_linux_init(&port);

    char protocols[512];
    if (snprintf(protocols, sizeof(protocols), "koios.console.v1, ticket.%s", ticket) >= (int)sizeof(protocols)) {
        fprintf(stderr, "koios-console: the ticket is too long\n");
        return 2;
    }
    const ks_config_t cfg = {
        .role = KS_ROLE_OPERATOR,
        .url = url,
        .protocols = protocols,
        .in_fd = STDIN_FILENO,
        .out_fd = STDOUT_FILENO,
    };
    char reason[200] = "";
    const int rc = ks_run(&cfg, reason, sizeof(reason));
    if (rc != KS_OK) {
        fprintf(stderr, "koios-console: no session: %s\n", reason[0] ? reason : "it did not start");
        return 1;
    }
    return 0;
}
