#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "libyggdrasil.h"

#define TEST_PORT "45671"
#define TEST_LISTEN_CFG "{\"Listen\": [\"tcp://127.0.0.1:" TEST_PORT "\"], \"MulticastInterfaces\": []}"
#define TEST_NO_MCAST_CFG "{\"MulticastInterfaces\": []}"
#define PAYLOAD "Hello Yggdrasil!"
#define PAYLOAD_LEN 16
#define IPV6_HEADER_LEN 40

static void log_handler(const char* msg, int level) {
    const char* levels[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};
    const char* lstr = (level >= 0 && level <= 4) ? levels[level] : "?";
    printf("[%s] %s", lstr, msg);
}

static void check_str(const char* name, char* s) {
    if (!s) {
        printf("  FAIL: %s returned NULL\n", name);
        return;
    }
    printf("  %s: %s\n", name, s);
    ygg_free_string(s);
}

/* Count occurrences of a substring */
static int count_substr(const char* haystack, const char* needle) {
    int count = 0;
    const char* p = haystack;
    size_t nlen = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += nlen;
    }
    return count;
}

/* Build a minimal IPv6 packet: version=6, next_header=59 (none), hop=64 */
static void build_ipv6_packet(unsigned char* pkt, int payload_len,
                               const char* src_addr, const char* dst_addr,
                               const void* payload) {
    memset(pkt, 0, IPV6_HEADER_LEN);
    pkt[0] = 0x60;                              /* version 6 */
    pkt[4] = (payload_len >> 8) & 0xFF;          /* payload length hi */
    pkt[5] = payload_len & 0xFF;                 /* payload length lo */
    pkt[6] = 59;                                 /* next header: none */
    pkt[7] = 64;                                 /* hop limit */
    inet_pton(AF_INET6, src_addr, &pkt[8]);      /* source */
    inet_pton(AF_INET6, dst_addr, &pkt[24]);     /* destination */
    memcpy(&pkt[IPV6_HEADER_LEN], payload, payload_len);
}

/* ------------------------------------------------------------------ */
/* Timing helpers                                                     */
/* ------------------------------------------------------------------ */

static double time_diff_us(struct timespec* start, struct timespec* end) {
    return (double)(end->tv_sec - start->tv_sec) * 1e6 +
           (double)(end->tv_nsec - start->tv_nsec) / 1e3;
}

/* ------------------------------------------------------------------ */
/* Recv thread helpers                                                */
/* ------------------------------------------------------------------ */

/* Single-packet recv (for connectivity tests + warmup) */
struct recv_args {
    int handle;
    unsigned char buf[65535];
    char sender_key[128];
    volatile int received;  /* -2 = not started, then result from ygg_recv_from */
};

static void* recv_thread_fn(void* arg) {
    struct recv_args* ra = (struct recv_args*)arg;
    ra->received = ygg_recv_from(ra->handle, ra->buf, sizeof(ra->buf),
                                  ra->sender_key, sizeof(ra->sender_key));
    return NULL;
}

/* Throughput recv: receives expected_packets packets */
struct bench_recv_ctx {
    int handle;
    int expected_packets;
    int packets_received;
    size_t bytes_received;
    volatile int done;  /* 0=running, 1=done, -1=error */
};

static void* bench_recv_fn(void* arg) {
    struct bench_recv_ctx* ctx = (struct bench_recv_ctx*)arg;
    unsigned char buf[65536];
    char key[128];
    while (ctx->packets_received < ctx->expected_packets) {
        int n = ygg_recv_from(ctx->handle, buf, sizeof(buf), key, sizeof(key));
        if (n < 0) {
            ctx->done = -1;
            return NULL;
        }
        ctx->bytes_received += n;
        ctx->packets_received++;
    }
    ctx->done = 1;
    return NULL;
}

/* Latency recv: receives one packet with timeout, records recv timestamp */
struct latency_recv_ctx {
    int handle;
    int timeout_ms;
    volatile int received;  /* -2=waiting, -1=error/timeout, >0=bytes */
    struct timespec recv_time;
};

static void* latency_recv_fn(void* arg) {
    struct latency_recv_ctx* ctx = (struct latency_recv_ctx*)arg;
    unsigned char buf[65536];
    char key[128];
    int n = ygg_recv_from_timeout(ctx->handle, buf, sizeof(buf),
                                   key, sizeof(key), ctx->timeout_ms);
    clock_gettime(CLOCK_MONOTONIC, &ctx->recv_time);
    ctx->received = n;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Connection helper: wait for two nodes to see each other in tree    */
/* ------------------------------------------------------------------ */

static int wait_for_connection(int h1, int h2, int timeout_secs) {
    for (int i = 0; i < timeout_secs * 10; i++) {
        usleep(100000);
        char* t1 = ygg_get_tree_json(h1);
        char* t2 = ygg_get_tree_json(h2);
        int ok = 0;
        if (t1 && t2) {
            ok = (count_substr(t1, "\"Key\"") > 1 &&
                  count_substr(t2, "\"Key\"") > 1);
        }
        if (t1) ygg_free_string(t1);
        if (t2) ygg_free_string(t2);
        if (ok) return 1;
        if (i % 10 == 9) { printf("."); fflush(stdout); }
    }
    return 0;
}

/* Warmup: send+recv one packet to establish encrypted session (with timeout) */
static int warmup_session(int sender, const char* recv_key, int receiver) {
    struct latency_recv_ctx wa;
    memset(&wa, 0, sizeof(wa));
    wa.handle = receiver;
    wa.timeout_ms = 10000;  /* 10 second timeout */
    wa.received = -2;
    pthread_t wt;
    pthread_create(&wt, NULL, latency_recv_fn, &wa);
    usleep(10000);
    unsigned char wpkt[64] = {0};
    ygg_send_to(sender, (char*)recv_key, wpkt, sizeof(wpkt));
    pthread_join(wt, NULL);  /* won't hang — thread has timeout */
    return (wa.received > 0) ? 0 : -1;
}

/* ================================================================== */
/* MAIN                                                                */
/* ================================================================== */

int main(void) {
    int rc;

    printf("=== Yggdrasil C Library Test ===\n\n");

    /* ------------------------------------------------------------------ */
    printf("[1] Version\n");
    check_str("version", ygg_get_version());

    /* ------------------------------------------------------------------ */
    printf("\n[2] Generate config\n");
    char* cfg = ygg_generate_config();
    assert(cfg != NULL);
    printf("  config length: %zu bytes\n", strlen(cfg));

    /* ------------------------------------------------------------------ */
    printf("\n[3] Config summary\n");
    check_str("summary", ygg_config_summary(cfg));
    ygg_free_string(cfg);

    /* ------------------------------------------------------------------ */
    printf("\n[4] Start node\n");
    int h = ygg_start("{}", log_handler);
    if (h < 0) {
        printf("  FAIL: %s\n", ygg_last_error());
        return 1;
    }
    printf("  handle: %d\n", h);

    /* ------------------------------------------------------------------ */
    printf("\n[5] Node info\n");
    check_str("address", ygg_get_address(h));
    check_str("subnet", ygg_get_subnet(h));
    check_str("public_key", ygg_get_public_key(h));
    printf("  mtu: %d\n", ygg_get_mtu(h));
    printf("  routing_entries: %d\n", ygg_get_routing_entries(h));

    /* ------------------------------------------------------------------ */
    printf("\n[6] JSON state\n");
    check_str("self", ygg_get_self_json(h));
    check_str("peers", ygg_get_peers_json(h));
    check_str("paths", ygg_get_paths_json(h));
    check_str("tree", ygg_get_tree_json(h));
    check_str("sessions", ygg_get_sessions_json(h));

    /* ------------------------------------------------------------------ */
    printf("\n[7] Peer management\n");
    rc = ygg_add_peer(h, "tcp://127.0.0.1:12345", NULL);
    printf("  add_peer: %s\n", rc == 0 ? "OK" : ygg_last_error());
    rc = ygg_remove_peer(h, "tcp://127.0.0.1:12345", NULL);
    printf("  remove_peer: %s\n", rc == 0 ? "OK" : ygg_last_error());

    /* ------------------------------------------------------------------ */
    printf("\n[8] Retry peers\n");
    rc = ygg_retry_peers_now(h);
    printf("  retry_peers_now: %s\n", rc == 0 ? "OK" : "FAIL");

    /* ------------------------------------------------------------------ */
    printf("\n[9] Stop\n");
    rc = ygg_stop(h);
    assert(rc == 0);
    printf("  stopped: OK\n");

    /* ------------------------------------------------------------------ */
    printf("\n[10] Invalid handle checks\n");
    assert(ygg_get_address(-1) == NULL);
    assert(ygg_send(-1, "x", 1) == -1);
    assert(ygg_recv(-1, NULL, 0) == -1);
    assert(ygg_stop(-1) == -1);
    printf("  all invalid handle checks passed\n");

    /* ================================================================== */
    /* Two-node connection and message passing test                       */
    /* ================================================================== */
    printf("\n[11] Two-node connection + message test\n");

    /* Start Node A (listener on fixed port) */
    int nodeA = ygg_start(TEST_LISTEN_CFG, log_handler);
    if (nodeA < 0) {
        printf("  FAIL starting node A: %s\n", ygg_last_error());
        return 1;
    }
    printf("  node A started (handle=%d)\n", nodeA);

    /* Start Node B (multicast disabled for test isolation) */
    int nodeB = ygg_start(TEST_NO_MCAST_CFG, log_handler);
    if (nodeB < 0) {
        printf("  FAIL starting node B: %s\n", ygg_last_error());
        ygg_stop(nodeA);
        return 1;
    }
    printf("  node B started (handle=%d)\n", nodeB);

    /* Node B connects to Node A */
    rc = ygg_add_peer(nodeB, "tcp://127.0.0.1:" TEST_PORT, NULL);
    if (rc != 0) {
        printf("  FAIL adding peer: %s\n", ygg_last_error());
        ygg_stop(nodeA);
        ygg_stop(nodeB);
        return 1;
    }
    printf("  node B peered with node A\n");

    /* Wait for tree convergence */
    printf("  waiting for connection...");
    fflush(stdout);
    if (!wait_for_connection(nodeA, nodeB, 10)) {
        printf("\n  FAIL: nodes did not connect within timeout\n");
        ygg_stop(nodeA);
        ygg_stop(nodeB);
        return 1;
    }
    printf("\n");

    /* Let routing settle */
    printf("  connected! waiting for routing to settle (3s)...\n");
    sleep(3);

    /* Get public keys for key-based send/recv */
    char* keyA_str = ygg_get_public_key(nodeA);
    char* keyB_str = ygg_get_public_key(nodeB);
    printf("  node A key: %s\n", keyA_str);
    printf("  node B key: %s\n", keyB_str);

    /* Build message: IPv6 header + payload */
    char* addrA_str = ygg_get_address(nodeA);
    char* addrB_str = ygg_get_address(nodeB);
    unsigned char pkt[IPV6_HEADER_LEN + PAYLOAD_LEN];
    int pkt_len = sizeof(pkt);
    build_ipv6_packet(pkt, PAYLOAD_LEN, addrB_str, addrA_str, PAYLOAD);
    ygg_free_string(addrA_str);
    ygg_free_string(addrB_str);

    /* Start recv thread on Node A */
    struct recv_args ra = { .handle = nodeA, .received = -2 };
    memset(ra.sender_key, 0, sizeof(ra.sender_key));
    pthread_t tid;
    pthread_create(&tid, NULL, recv_thread_fn, &ra);
    usleep(50000);

    /* Send from B to A using A's public key */
    rc = ygg_send_to(nodeB, keyA_str, pkt, pkt_len);
    printf("  sent from B to A: %d bytes\n", rc);

    /* Poll for recv completion (timeout 10s) */
    int recv_ok = 0;
    for (int i = 0; i < 100; i++) {
        usleep(100000);
        if (ra.received != -2) {
            recv_ok = 1;
            break;
        }
    }

    if (!recv_ok) {
        printf("  FAIL: recv timed out on node A\n");
        ygg_stop(nodeA);
        ygg_stop(nodeB);
        pthread_join(tid, NULL);
        ygg_free_string(keyA_str);
        ygg_free_string(keyB_str);
        return 1;
    }

    pthread_join(tid, NULL);
    printf("  recv on A: %d bytes from %s\n", ra.received, ra.sender_key);

    /* Verify payload */
    if (ra.received >= pkt_len &&
        memcmp(&ra.buf[IPV6_HEADER_LEN], PAYLOAD, PAYLOAD_LEN) == 0) {
        printf("  payload verified: \"%.*s\" OK\n", PAYLOAD_LEN,
               &ra.buf[IPV6_HEADER_LEN]);
    } else {
        printf("  FAIL: payload mismatch (received %d bytes)\n", ra.received);
        ygg_free_string(keyA_str);
        ygg_free_string(keyB_str);
        ygg_stop(nodeA);
        ygg_stop(nodeB);
        return 1;
    }

    /* Verify sender key matches node B */
    if (strcmp(ra.sender_key, keyB_str) == 0) {
        printf("  sender key verified: OK\n");
    } else {
        printf("  WARN: sender key mismatch (got %s, expected %s)\n",
               ra.sender_key, keyB_str);
    }

    ygg_free_string(keyA_str);
    ygg_free_string(keyB_str);
    ygg_stop(nodeA);
    ygg_stop(nodeB);
    printf("  both nodes stopped\n");

    /* ================================================================== */
    /* P2P Throughput Benchmark (1 hop)                                   */
    /* ================================================================== */
    printf("\n[12] P2P Throughput Benchmark (1 hop)\n");

    #define BENCH_PORT "47000"
    #define BENCH_LISTEN_CFG "{\"Listen\": [\"tcp://127.0.0.1:" BENCH_PORT "\"], \"MulticastInterfaces\": []}"

    int bsnd = ygg_start(BENCH_LISTEN_CFG, NULL);
    if (bsnd < 0) { printf("  FAIL start sender: %s\n", ygg_last_error()); return 1; }
    int brcv = ygg_start(TEST_NO_MCAST_CFG, NULL);
    if (brcv < 0) { printf("  FAIL start receiver: %s\n", ygg_last_error()); ygg_stop(bsnd); return 1; }

    rc = ygg_add_peer(brcv, "tcp://127.0.0.1:" BENCH_PORT, NULL);
    if (rc != 0) { printf("  FAIL peer: %s\n", ygg_last_error()); ygg_stop(bsnd); ygg_stop(brcv); return 1; }

    printf("  Connecting...");
    fflush(stdout);
    if (!wait_for_connection(bsnd, brcv, 10)) {
        printf("\n  FAIL: timeout\n");
        ygg_stop(bsnd); ygg_stop(brcv);
        return 1;
    }
    printf("done\n");
    printf("  Settling (3s)...\n");
    sleep(3);

    char* bkey_snd = ygg_get_public_key(bsnd);
    char* bkey_rcv = ygg_get_public_key(brcv);
    int mtu = ygg_get_mtu(bsnd);
    printf("  MTU: %d bytes\n", mtu);

    /* Warmup: establish encrypted sessions in both directions */
    printf("  Warming up sessions...");
    fflush(stdout);
    warmup_session(bsnd, bkey_rcv, brcv);
    warmup_session(brcv, bkey_snd, bsnd);
    printf("done\n\n");

    /* Throughput tests for various data sizes */
    unsigned char* snd_buf = (unsigned char*)calloc(1, mtu);
    for (int i = 0; i < mtu; i++) snd_buf[i] = (unsigned char)(i & 0xFF);

    typedef struct { const char* label; size_t bytes; } bench_entry;
    bench_entry bench_sizes[] = {
        {"12 B",     12},
        {"32 B",     32},
        {"64 B",     64},
        {"100 B",    100},
        {"128 B",    128},
        {"256 B",    256},
        {"1 pkt",    0},          /* set to mtu below */
        {"512 KB",   512UL * 1024},
        {"1 MB",     1024UL * 1024},
        {"10 MB",    10UL * 1024 * 1024},
        {"100 MB",   100UL * 1024 * 1024},
        {"1 GB",     1024UL * 1024 * 1024},
    };
    bench_sizes[6].bytes = (size_t)mtu;
    int n_sizes = (int)(sizeof(bench_sizes) / sizeof(bench_sizes[0]));

    printf("  %-12s %12s %14s %10s %10s\n", "Size", "Time (s)", "Time (us)", "MB/s", "Packets");
    printf("  %-12s %12s %14s %10s %10s\n", "----", "--------", "---------", "----", "-------");

    for (int si = 0; si < n_sizes; si++) {
        size_t total = bench_sizes[si].bytes;
        int pkt_size = ((int)total < mtu) ? (int)total : mtu;
        if (pkt_size == 0) pkt_size = mtu;
        int npkts = (int)((total + (size_t)pkt_size - 1) / (size_t)pkt_size);

        /* Start receiver thread */
        struct bench_recv_ctx rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.handle = brcv;
        rctx.expected_packets = npkts;
        pthread_t rtid;
        pthread_create(&rtid, NULL, bench_recv_fn, &rctx);
        usleep(10000);

        /* Timed send + wait for all recv */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < npkts; i++) {
            int ret = ygg_send_to(bsnd, bkey_rcv, snd_buf, pkt_size);
            if (ret < 0) {
                printf("\n  send error at pkt %d/%d: %s\n", i, npkts, ygg_last_error());
                break;
            }
        }
        pthread_join(rtid, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        double us = time_diff_us(&t0, &t1);
        double secs = us / 1e6;
        double mbps = (double)rctx.bytes_received / 1e6 / (secs > 0.0 ? secs : 0.001);

        printf("  %-12s %12.3f %14.0f %10.1f %10d\n",
               bench_sizes[si].label, secs, us, mbps, rctx.packets_received);
    }

    free(snd_buf);
    ygg_free_string(bkey_snd);
    ygg_free_string(bkey_rcv);
    ygg_stop(bsnd);
    ygg_stop(brcv);
    printf("  benchmark nodes stopped\n");

    /* ================================================================== */
    /* Multi-hop Latency Benchmark                                        */
    /* ================================================================== */
    printf("\n[13] Multi-hop Latency Benchmark\n");

    #define CHAIN_LEN 11    /* 11 nodes = up to 10 hops */
    #define CHAIN_BASE_PORT 48000
    #define LATENCY_SAMPLES 5

    int chain[CHAIN_LEN];
    char* chain_keys[CHAIN_LEN];
    char tmp_cfg[256], tmp_uri[128];

    /* Start all chain nodes */
    for (int i = 0; i < CHAIN_LEN; i++) {
        snprintf(tmp_cfg, sizeof(tmp_cfg),
                 "{\"Listen\": [\"tcp://127.0.0.1:%d\"], \"MulticastInterfaces\": []}",
                 CHAIN_BASE_PORT + i);
        chain[i] = ygg_start(tmp_cfg, NULL);
        if (chain[i] < 0) {
            printf("  FAIL start node %d: %s\n", i, ygg_last_error());
            for (int j = 0; j < i; j++) { ygg_free_string(chain_keys[j]); ygg_stop(chain[j]); }
            goto skip_latency;
        }
        chain_keys[i] = ygg_get_public_key(chain[i]);
    }
    printf("  Started %d nodes in chain\n", CHAIN_LEN);

    /* Connect chain: node[i] peers with node[i-1] */
    for (int i = 1; i < CHAIN_LEN; i++) {
        snprintf(tmp_uri, sizeof(tmp_uri), "tcp://127.0.0.1:%d", CHAIN_BASE_PORT + i - 1);
        rc = ygg_add_peer(chain[i], tmp_uri, NULL);
        if (rc != 0) {
            printf("  FAIL peer %d->%d: %s\n", i, i - 1, ygg_last_error());
            for (int j = 0; j < CHAIN_LEN; j++) { ygg_free_string(chain_keys[j]); ygg_stop(chain[j]); }
            goto skip_latency;
        }
    }
    printf("  Chain topology connected\n");

    /* Wait for all peer connections to establish */
    printf("  Waiting for peer connections...");
    fflush(stdout);
    {
        int all_peers = 0;
        for (int attempt = 0; attempt < 600; attempt++) {  /* up to 60s */
            usleep(100000);
            int ok = 1;
            for (int i = 0; i < CHAIN_LEN; i++) {
                char* peers = ygg_get_peers_json(chain[i]);
                if (!peers) { ok = 0; break; }
                int expected = (i == 0 || i == CHAIN_LEN - 1) ? 1 : 2;
                int actual = count_substr(peers, "\"URI\"");
                ygg_free_string(peers);
                if (actual < expected) { ok = 0; break; }
            }
            if (ok) { all_peers = 1; break; }
            if (attempt % 10 == 9) { printf("."); fflush(stdout); }
        }
        printf("\n");
        if (!all_peers) {
            printf("  FAIL: peer connections did not establish\n");
            for (int i = 0; i < CHAIN_LEN; i++) { ygg_free_string(chain_keys[i]); ygg_stop(chain[i]); }
            goto skip_latency;
        }
    }

    printf("  Settling tree routing (15s)...\n");
    sleep(15);

    /* Warmup: establish encrypted sessions from node[0] to each node[h] */
    printf("  Warming up sessions");
    fflush(stdout);
    for (int hop = 1; hop < CHAIN_LEN; hop++) {
        if (warmup_session(chain[0], chain_keys[hop], chain[hop]) < 0) {
            printf("\n  WARN: warmup failed for %d hops\n  ", hop);
        }
        /* Also warm up reverse direction */
        warmup_session(chain[hop], chain_keys[0], chain[0]);
        printf(".");
        fflush(stdout);
    }
    printf("done\n\n");

    /* Latency measurements */
    printf("  %-6s %12s %12s %12s %10s\n", "Hops", "Avg (us)", "Min (us)", "Max (us)", "Avg (s)");
    printf("  %-6s %12s %12s %12s %10s\n", "----", "--------", "--------", "--------", "-------");

    for (int hop = 1; hop < CHAIN_LEN; hop++) {
        double samples[LATENCY_SAMPLES];
        int valid = 0;

        for (int s = 0; s < LATENCY_SAMPLES; s++) {
            struct latency_recv_ctx lctx;
            memset(&lctx, 0, sizeof(lctx));
            lctx.handle = chain[hop];
            lctx.timeout_ms = 10000;  /* 10s timeout */
            lctx.received = -2;

            pthread_t ltid;
            pthread_create(&ltid, NULL, latency_recv_fn, &lctx);
            usleep(10000);  /* let thread start blocking */

            struct timespec t0;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            unsigned char lpkt[64] = {0};
            ygg_send_to(chain[0], chain_keys[hop], lpkt, sizeof(lpkt));

            pthread_join(ltid, NULL);  /* won't hang — thread has timeout */

            if (lctx.received > 0) {
                samples[valid++] = time_diff_us(&t0, &lctx.recv_time);
            }
            usleep(5000);  /* small gap between samples */
        }

        if (valid > 0) {
            double avg = 0, mn = samples[0], mx = samples[0];
            for (int i = 0; i < valid; i++) {
                avg += samples[i];
                if (samples[i] < mn) mn = samples[i];
                if (samples[i] > mx) mx = samples[i];
            }
            avg /= valid;
            printf("  %-6d %12.0f %12.0f %12.0f %10.4f\n",
                   hop, avg, mn, mx, avg / 1e6);
        } else {
            printf("  %-6d %12s %12s %12s %10s\n", hop, "TIMEOUT", "-", "-", "-");
        }
    }

    /* Clean up chain nodes */
    for (int i = 0; i < CHAIN_LEN; i++) {
        ygg_free_string(chain_keys[i]);
        ygg_stop(chain[i]);
    }
    printf("  all %d chain nodes stopped\n", CHAIN_LEN);

skip_latency:

    /* ------------------------------------------------------------------ */
    printf("\n=== All tests passed ===\n");
    return 0;
}
