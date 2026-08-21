/* SPDX-License-Identifier: MIT
 *
 * secoc_recv.c
 *
 * Receives CAN FD frames on a SocketCAN interface, parses out a
 * SecOC-style authenticated PDU:
 *
 *   [ Authentic PDU payload ] [ Freshness (truncated) ] [ MAC (truncated) ]
 *
 * recomputes the CMAC locally using the same key/config as secoc_send.c,
 * and reports whether the MAC and freshness are valid.
 *
 * IMPORTANT: the layout/lengths/algorithm below must match secoc_send.c
 * (and, for real interop, your actual AUTOSAR SecOC config) exactly.
 * See the comments in secoc_send.c for what to change and why.
 *
 * Build:
 *   gcc -O2 -Wall secoc_recv.c -o secoc_recv -lcrypto
 *
 * Usage:
 *   ./secoc_recv <iface> [can_id_hex_filter]
 *   e.g. ./secoc_recv vcan0 123
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#include <openssl/cmac.h>
#include <openssl/evp.h>

/* ---- SecOC config: MUST MATCH secoc_send.c ---- */

#define DATA_ID               0x1234u
#define AUTHENTIC_PAYLOAD_LEN 8

#define FRESHNESS_FULL_LEN    4   /* internally tracked freshness width */
#define FRESHNESS_TX_LEN      2   /* bytes actually carried on the wire */

#define MAC_FULL_LEN          16  /* CMAC-AES128 output length */
#define MAC_TX_LEN            4   /* truncated MAC length carried on the wire */

static const unsigned char secoc_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

/* ------------------------------------------------------------------- */

/* Last accepted freshness value per Data ID - naive single-PDU tracking.
 * A real SecOC RTE tracks this per PDU/sender and reconstructs the full
 * freshness counter from the truncated value; this is a simplified demo
 * that just compares the reconstructed value against the last seen one. */
static uint32_t last_freshness = 0;
static int have_last_freshness = 0;

static size_t build_mac_input(unsigned char *out,
                               uint16_t data_id,
                               const unsigned char *freshness_full,
                               size_t freshness_full_len,
                               const unsigned char *payload,
                               size_t payload_len)
{
    size_t off = 0;
    out[off++] = (data_id >> 8) & 0xFF;
    out[off++] = data_id & 0xFF;
    memcpy(out + off, freshness_full, freshness_full_len);
    off += freshness_full_len;
    memcpy(out + off, payload, payload_len);
    off += payload_len;
    return off;
}

static int compute_cmac(const unsigned char *key, size_t key_len,
                         const unsigned char *msg, size_t msg_len,
                         unsigned char *mac_out, size_t *mac_out_len)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx)
        return -1;
    if (!CMAC_Init(ctx, key, key_len, EVP_aes_128_cbc(), NULL) ||
        !CMAC_Update(ctx, msg, msg_len) ||
        !CMAC_Final(ctx, mac_out, mac_out_len)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    CMAC_CTX_free(ctx);
    return 0;
}

/* Reconstruct a full freshness value from the truncated one carried on
 * the wire. Real SecOC does window-based reconstruction against the
 * last known value; here we do the simplest possible version: assume
 * the high-order bytes are unchanged from last_freshness and only the
 * low FRESHNESS_TX_LEN bytes moved. Good enough for bench testing with
 * a monotonically increasing counter that doesn't wrap during the test. */
static uint32_t reconstruct_freshness(const unsigned char *freshness_tx)
{
    uint32_t tx_val = 0;
    for (int i = 0; i < FRESHNESS_TX_LEN; i++)
        tx_val = (tx_val << 8) | freshness_tx[i];

    uint32_t high_mask = ~((1u << (8 * FRESHNESS_TX_LEN)) - 1);
    uint32_t reconstructed = (last_freshness & high_mask) | tx_val;

    if (have_last_freshness && reconstructed < last_freshness) {
        reconstructed += (1u << (8 * FRESHNESS_TX_LEN));
    }
    return reconstructed;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <iface> [can_id_hex_filter]\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    int have_filter = 0;
    uint32_t filter_id = 0;
    if (argc >= 3) {
        filter_id = (uint32_t)strtoul(argv[2], NULL, 16);
        have_filter = 1;
    }

    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    int enable_fd = 1;
    if (setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                   &enable_fd, sizeof(enable_fd)) < 0) {
        perror("setsockopt CAN_RAW_FD_FRAMES");
        close(sock);
        return 1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return 1;
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("Listening for SecOC frames on %s\n", iface);
    if (have_filter)
        printf("  filter: id=0x%03X\n", filter_id);

    for (;;) {
        struct canfd_frame frame;
        ssize_t nbytes = read(sock, &frame, sizeof(frame));
        if (nbytes < 0) {
            perror("read");
            break;
        }
        if (nbytes != sizeof(struct canfd_frame)) {
            /* classic CAN frame (or short read) - not a CAN FD frame, skip */
            continue;
        }
        if (have_filter && (frame.can_id & CAN_EFF_MASK) != filter_id)
            continue;

        size_t expected_len = AUTHENTIC_PAYLOAD_LEN + FRESHNESS_TX_LEN + MAC_TX_LEN;
        if (frame.len < expected_len) {
            printf("[id=0x%03X] frame too short (%u bytes, expected >= %zu) - skipping\n",
                   frame.can_id, frame.len, expected_len);
            continue;
        }

        unsigned char *payload      = frame.data;
        unsigned char *freshness_tx = frame.data + AUTHENTIC_PAYLOAD_LEN;
        unsigned char *mac_tx       = frame.data + AUTHENTIC_PAYLOAD_LEN + FRESHNESS_TX_LEN;

        /* Reconstruct full freshness and check it's newer than last accepted
         * (basic anti-replay check) */
        uint32_t freshness_full_val = reconstruct_freshness(freshness_tx);
        int freshness_ok = (!have_last_freshness) || (freshness_full_val > last_freshness);

        unsigned char freshness_full[FRESHNESS_FULL_LEN];
        for (int i = 0; i < FRESHNESS_FULL_LEN; i++) {
            int shift = 8 * (FRESHNESS_FULL_LEN - 1 - i);
            freshness_full[i] = (shift < 32) ? (unsigned char)((freshness_full_val >> shift) & 0xFF) : 0;
        }

        /* Recompute MAC and compare */
        unsigned char mac_input[2 + FRESHNESS_FULL_LEN + AUTHENTIC_PAYLOAD_LEN];
        size_t mac_input_len = build_mac_input(mac_input, DATA_ID,
                                                freshness_full, FRESHNESS_FULL_LEN,
                                                payload, AUTHENTIC_PAYLOAD_LEN);

        unsigned char mac_full[EVP_MAX_MD_SIZE];
        size_t mac_full_len = 0;
        int mac_ok = 0;
        if (compute_cmac(secoc_key, sizeof(secoc_key),
                          mac_input, mac_input_len,
                          mac_full, &mac_full_len) == 0 &&
            mac_full_len >= MAC_TX_LEN) {
            mac_ok = (memcmp(mac_full, mac_tx, MAC_TX_LEN) == 0);
        }

        printf("[id=0x%03X] freshness=%u mac=%s freshness_check=%s -> %s\n",
               frame.can_id,
               freshness_full_val,
               mac_ok ? "OK" : "FAIL",
               freshness_ok ? "OK" : "STALE/REPLAY",
               (mac_ok && freshness_ok) ? "ACCEPT" : "REJECT");

        if (mac_ok && freshness_ok) {
            last_freshness = freshness_full_val;
            have_last_freshness = 1;
        }
    }

    close(sock);
    return 0;
}