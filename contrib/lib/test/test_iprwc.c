/*
 * Test: ygg_send / ygg_recv (ipv6rwc path)
 *
 * The existing test_yggdrasil uses ygg_send_to / ygg_recv_from which
 * bypasses ipv6rwc entirely. Our GDExtension uses ygg_send/ygg_recv
 * which goes through the ipv6rwc layer (address-based routing).
 *
 * This test verifies that ygg_send/ygg_recv actually works end-to-end.
 * Both nodes have recv threads running (matching the GDExtension pattern).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "libyggdrasil.h"

#define LISTEN_PORT "46500"
#define LISTEN_CFG "{\"Listen\": [\"tcp://127.0.0.1:" LISTEN_PORT "\"], \"MulticastInterfaces\": []}"
#define NO_MCAST_CFG "{\"MulticastInterfaces\": []}"

#define GAME_PORT 49152
#define IPV6_HDR_LEN 40
#define UDP_HDR_LEN 8

static void log_handler(const char* msg, int level) {
    const char* levels[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};
    const char* lstr = (level >= 0 && level <= 4) ? levels[level] : "?";
    printf("  [%s] %s", lstr, msg);
}

static int count_substr(const char* haystack, const char* needle) {
    int count = 0;
    const char* p = haystack;
    size_t nlen = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) { count++; p += nlen; }
    return count;
}

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

/* --------------------------------------------------------------- */
/* Build IPv6+UDP packet (same as GDExtension _send_ipv6_packet)   */
/* --------------------------------------------------------------- */

static void write_u16_be(unsigned char* dst, unsigned short val) {
    dst[0] = (val >> 8) & 0xFF;
    dst[1] = val & 0xFF;
}

static int build_ipv6_udp_packet(
    unsigned char* pkt,
    const char* src_addr_str,
    const char* dst_addr_str,
    unsigned short src_port,
    unsigned short dst_port,
    const unsigned char* payload,
    int payload_len
) {
    int total = IPV6_HDR_LEN + UDP_HDR_LEN + payload_len;
    memset(pkt, 0, total);

    /* IPv6 header */
    pkt[0] = 0x60;  /* version 6 */
    unsigned short ipv6_payload_len = UDP_HDR_LEN + payload_len;
    write_u16_be(&pkt[4], ipv6_payload_len);
    pkt[6] = 17;  /* next header: UDP */
    pkt[7] = 64;  /* hop limit */
    inet_pton(AF_INET6, src_addr_str, &pkt[8]);   /* source addr */
    inet_pton(AF_INET6, dst_addr_str, &pkt[24]);  /* dest addr */

    /* UDP header */
    write_u16_be(&pkt[40], src_port);
    write_u16_be(&pkt[42], dst_port);
    write_u16_be(&pkt[44], UDP_HDR_LEN + payload_len);
    write_u16_be(&pkt[46], 0);  /* checksum (not validated by ygg internal routing) */

    /* UDP payload */
    memcpy(&pkt[48], payload, payload_len);

    return total;
}

/* --------------------------------------------------------------- */
/* Recv thread for ygg_recv (blocking)                             */
/* --------------------------------------------------------------- */

struct iprwc_recv_args {
    int handle;
    unsigned char buf[65536];
    volatile int result;  /* -2 = not started, then ygg_recv return value */
};

static void* iprwc_recv_thread(void* arg) {
    struct iprwc_recv_args* ra = (struct iprwc_recv_args*)arg;
    ra->result = ygg_recv(ra->handle, ra->buf, sizeof(ra->buf));
    return NULL;
}

/* --------------------------------------------------------------- */
/* MAIN                                                            */
/* --------------------------------------------------------------- */

int main(void) {
    printf("=== ygg_send/ygg_recv (ipv6rwc) Test ===\n\n");

    /* ---- Start two nodes ---- */
    printf("[1] Starting nodes...\n");
    int nodeA = ygg_start(LISTEN_CFG, log_handler);
    assert(nodeA >= 0);
    printf("  Node A started (handle=%d)\n", nodeA);

    int nodeB = ygg_start(NO_MCAST_CFG, log_handler);
    assert(nodeB >= 0);
    printf("  Node B started (handle=%d)\n", nodeB);

    /* ---- Peer B -> A ---- */
    printf("\n[2] Peering B -> A...\n");
    int rc = ygg_add_peer(nodeB, "tcp://127.0.0.1:" LISTEN_PORT, NULL);
    assert(rc == 0);

    printf("  Waiting for tree convergence...");
    fflush(stdout);
    assert(wait_for_connection(nodeA, nodeB, 15));
    printf(" OK\n");

    printf("  Settling (3s)...\n");
    sleep(3);

    /* ---- Get addresses ---- */
    char* addrA = ygg_get_address(nodeA);
    char* addrB = ygg_get_address(nodeB);
    printf("\n[3] Addresses:\n");
    printf("  Node A: %s\n", addrA);
    printf("  Node B: %s\n", addrB);

    /* ---- Test: B -> A with recv threads on BOTH sides ---- */
    printf("\n[4] Test: ygg_send() B -> A (recv threads on BOTH nodes)\n");

    unsigned char test_payload[] = {0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    int payload_len = sizeof(test_payload);

    unsigned char pkt[512];
    int pkt_len = build_ipv6_udp_packet(
        pkt, addrB, addrA, GAME_PORT, GAME_PORT,
        test_payload, payload_len
    );
    printf("  Built IPv6+UDP packet: %d bytes (payload=%d)\n", pkt_len, payload_len);

    /* Start recv threads on BOTH nodes (this matches GDExtension pattern:
       both server and client have recv_thread running ygg_recv in a loop) */
    struct iprwc_recv_args raA, raB;
    memset(&raA, 0, sizeof(raA));
    memset(&raB, 0, sizeof(raB));
    raA.handle = nodeA;
    raA.result = -2;
    raB.handle = nodeB;
    raB.result = -2;

    pthread_t tidA, tidB;
    pthread_create(&tidA, NULL, iprwc_recv_thread, &raA);
    pthread_create(&tidB, NULL, iprwc_recv_thread, &raB);
    usleep(200000);  /* 200ms for threads to start blocking on ygg_recv */

    /* Send from B -> A */
    printf("  Sending B -> A via ygg_send()...\n");
    rc = ygg_send(nodeB, pkt, pkt_len);
    printf("  ygg_send() returned: %d", rc);
    if (rc < 0) {
        const char* err = ygg_last_error();
        printf(" ERROR: %s", err ? err : "(null)");
    }
    printf("\n");

    /* Wait for recv on A (timeout 15s - first send needs session warmup) */
    printf("  Waiting for ygg_recv() on A...");
    fflush(stdout);
    int recv_ok = 0;
    for (int i = 0; i < 150; i++) {
        usleep(100000);
        if (raA.result != -2) {
            recv_ok = 1;
            break;
        }
        if (i % 10 == 9) { printf("."); fflush(stdout); }
    }
    printf("\n");

    if (!recv_ok) {
        printf("  First packet timed out (expected for session warmup).\n");
        printf("  Sending 10 more packets with 500ms intervals...\n");
        for (int attempt = 0; attempt < 10; attempt++) {
            /* Rebuild packet (same payload) */
            rc = ygg_send(nodeB, pkt, pkt_len);
            printf("    send #%d: ygg_send()=%d", attempt + 1, rc);
            if (rc < 0) {
                const char* err = ygg_last_error();
                printf(" err=%s", err ? err : "(null)");
            }
            printf("\n");
            usleep(500000);
            if (raA.result != -2) {
                printf("    Packet arrived on retry #%d!\n", attempt + 1);
                recv_ok = 1;
                break;
            }
        }
    }

    if (recv_ok) {
        printf("  SUCCESS: ygg_recv() on A returned: %d bytes\n", raA.result);
        if (raA.result >= IPV6_HDR_LEN + UDP_HDR_LEN + payload_len) {
            unsigned char* recv_payload = &raA.buf[IPV6_HDR_LEN + UDP_HDR_LEN];
            if (memcmp(recv_payload, test_payload, payload_len) == 0) {
                printf("  Payload verified OK!\n");
            } else {
                printf("  Payload MISMATCH!\n");
            }
        }
    } else {
        printf("  FAIL: No packets received after all attempts.\n");
    }

    /* ---- Test reverse direction: A -> B ---- */
    printf("\n[5] Test: ygg_send() A -> B\n");

    /* raB's recv thread is already running */
    unsigned char pkt2[512];
    unsigned char payload2[] = {0x05, 0xCA, 0xFE, 0xBA, 0xBE, 0x04, 0x05, 0x06};
    int pkt2_len = build_ipv6_udp_packet(
        pkt2, addrA, addrB, GAME_PORT, GAME_PORT,
        payload2, sizeof(payload2)
    );

    printf("  Sending A -> B via ygg_send()...\n");
    rc = ygg_send(nodeA, pkt2, pkt2_len);
    printf("  ygg_send() returned: %d\n", rc);

    int recv_ok2 = 0;
    printf("  Waiting for ygg_recv() on B...");
    fflush(stdout);
    for (int i = 0; i < 100; i++) {
        usleep(100000);
        if (raB.result != -2) {
            recv_ok2 = 1;
            break;
        }
        if (i % 10 == 9) { printf("."); fflush(stdout); }
    }
    printf("\n");

    if (recv_ok2) {
        printf("  SUCCESS: ygg_recv() on B returned: %d bytes\n", raB.result);
        if (raB.result >= IPV6_HDR_LEN + UDP_HDR_LEN + (int)sizeof(payload2)) {
            unsigned char* rp = &raB.buf[IPV6_HDR_LEN + UDP_HDR_LEN];
            if (memcmp(rp, payload2, sizeof(payload2)) == 0) {
                printf("  Payload verified OK!\n");
            } else {
                printf("  Payload MISMATCH!\n");
            }
        }
    } else {
        printf("  FAIL: No packets received on B.\n");
    }

    /* ---- Cleanup ---- */
    printf("\n[6] Cleanup\n");
    ygg_free_string(addrA);
    ygg_free_string(addrB);
    ygg_stop(nodeA);
    ygg_stop(nodeB);
    pthread_join(tidA, NULL);
    pthread_join(tidB, NULL);
    printf("  Done.\n");

    int pass = recv_ok && recv_ok2;
    printf("\n=== %s ===\n", pass ? "ALL TESTS PASSED" : "TESTS FAILED");
    return pass ? 0 : 1;
}
