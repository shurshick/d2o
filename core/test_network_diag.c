/* Procfs fixtures exercise the real collector without depending on privileges. */
#define _POSIX_C_SOURCE 200809L
#include "network_diag.h"
#include "../runtime/d2k_diagnostics_files.h"
#include <assert.h>
#include <stdlib.h>
#include <sys/file.h>

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) return 2;
    assert(d2k_network_history_bytes() <= D2K_NETWORK_BUDGET);
    assert(!d2k_diag_network_toggle(argv[4], 1));
    uint64_t session = d2k_network_session(argv[4]);
    assert(session);
    int fd = d2k_network_open(argv[4], D2K_NETWORK_STATE, 1);
    assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
    d2k_network_history *history = d2k_network_history_map(fd, session);
    if (!history) return 1;
    d2k_network_controller_message c = {.header.pid = 22, .generation = 7, .limit = 4,
        .cpu_free_pct = 68, .mem_available_kib = UINT32_MAX};
    d2k_network_datapath_message d = {.header.pid = 21, .generation = 6, .queue = 2000,
        .queue_limit = 1024, .fail_open = 1, .netlink_port = 12345};
    int long_run = argc == 6 && !strcmp(argv[5], "long");
    int anomalies = argc == 6 && !strcmp(argv[5], "anomalies");
    unsigned count = long_run ? 30 * 60 * 25 : anomalies ? 300 : D2K_NETWORK_HISTORY + 3;
    for (unsigned i = 0; i < count; i++) {
        uint64_t now = 1000 + i * D2K_NET_DIAG_INTERVAL_MS;
        if (i % 4 == 0) {
            d.mono_ms = now;
            d.counters.packets = i;
            d.counters.verdict_samples = i;
            d.counters.verdict_max_us = 99;
        }
        if (long_run) {
            d.mono_ms = now;
            /* Four incidents with a second signal in the same incident window. */
            if (i >= 180 && i <= 930 && (i % 240 == 180 || i % 240 == 183))
                d.counters.enobufs++;
            if (i == 915) { d.generation++; d.counters.enobufs += 50; }
            c.queued = i % 30 == 2 ? 10 : 1;
        }
        if (anomalies) {
            d.mono_ms = i >= 190 && i <= 195 ? 379000 : now;
            d.counters.verdict_max_us = i == 180 ? 500000 : UINT64_MAX;
            d.counters.userspace_verdict_max_us = UINT64_MAX;
            d.counters.loop_max_us = i == 181 ? 1000000 : 200000;
            if (i == 182) {
                char path[512];
                assert(snprintf(path, sizeof(path), "%s/net/netfilter/nfnetlink_queue", argv[1]) > 0);
                FILE *queue = fopen(path, "w");
                assert(queue && fprintf(queue, "2000 12345 800 2 1600 2 3 4 1\n") > 0);
                assert(!fclose(queue));
            }
            if (i == 183) {
                c.counters.tcp_dial_deadlines += 3;
                c.counters.direct_verified++;
                c.counters.dns_valid_replies++;
                d.counters.tcp_prior_exchange_actions += 2;
                d.counters.udp_prior_exchange_actions++;
            }
            if (i == 184) {
                assert(!flock(fd, LOCK_UN));
                assert(d2k_network_request_incident(argv[4], now + 8000) < 0); /* stale */
                assert(!d2k_network_request_incident(argv[4], now));
                assert(!flock(fd, LOCK_EX | LOCK_NB));
            }
        }
        c.mono_ms = now;
        c.counters.dns_failures = i;
        d2k_network_history_sample(history, now, &c, &d, argv[1], argv[2], argv[3]);
    }
    d2k_network_history *copy = d2k_network_history_copy(fd, session);
    assert(copy && !d2k_network_history_copy(fd, session ^ 1));
    assert(!d2k_network_history_unmap(history, fd));
    assert(!d2k_network_history_copy(fd, session));
    close(fd);
    d2k_network_history_write(stdout, copy);
    free(copy);
    return ferror(stdout) ? 1 : 0;
}
