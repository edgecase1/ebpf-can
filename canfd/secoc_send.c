/* SPDX-License-Identifier: MIT
 *
 * secoc_send.c
 *
 * Builds an AUTOSAR-SecOC-style authenticated CAN FD PDU:
 *
 *   [ Authentic PDU payload ] [ Freshness (truncated) ] [ MAC (truncated) ]
 *
 * and transmits it over a SocketCAN interface (e.g. vcan0) as a CAN FD
 * frame.
 *
 * IMPORTANT: SecOC is not a wire format on its own - the exact layout
 * (Data ID / freshness length / MAC length / MAC algorithm / how the
 * MAC input is constructed) is defined per-PDU in your AUTOSAR SecOC
 * module config. The values below (CMAC-AES128, 2-byte truncated
 * freshness, 4-byte truncated MAC, MAC input = DataID || Freshness ||
 * Payload) are a common convention, NOT a standard you can assume
 * matches your ECU. Adjust the #defines and build_mac_input() to match
 * your actual config before this will interoperate with a real target.
 *
 * Build:
 *   gcc -O2 -Wall secoc_send.c -o secoc_send -lcrypto
 *
 * Usage:
 *   ./secoc_send <iface> <can_id_hex> <freshness_counter>
 *   e.g. ./secoc_send vcan0 123 42
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
 
/* ---- SecOC config: EDIT THESE to match your target's SecOC setup ---- */
 
#define DATA_ID              0x1234u   /* per-PDU identifier, config-specific */
#define AUTHENTIC_PAYLOAD    { 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44 }
#define AUTHENTIC_PAYLOAD_LEN 8
 
#define FRESHNESS_FULL_LEN   4   /* bytes of freshness counter maintained internally */
#define FRESHNESS_TX_LEN     2   /* bytes of freshness actually transmitted (truncated) */
 
#define MAC_FULL_LEN         16  /* CMAC-AES128 output length */
#define MAC_TX_LEN           4   /* truncated MAC length actually transmitted */
 
/* 16-byte AES-128 key. NEVER hardcode a real key in shipped code -
 * this is a placeholder for bench/test use only. */
static const unsigned char secoc_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
 
/* ---------------------------------------------------------------------- */
 
/* Build the buffer that gets fed into the MAC algorithm.
 * Common convention: DataID || Freshness (full) || Authentic Payload.
 * MUST match what your receiving ECU actually computes. */
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
 
    if (!CMAC_Init(ctx, key, key_len, EVP_aes_128_cbc(), NULL)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    if (!CMAC_Update(ctx, msg, msg_len)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    if (!CMAC_Final(ctx, mac_out, mac_out_len)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
 
    CMAC_CTX_free(ctx);
    return 0;
}
 
int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <iface> <can_id_hex> <freshness_counter>\n", argv[0]);
        fprintf(stderr, "  e.g. %s vcan0 123 42\n", argv[0]);
        return 1;
    }
 
    const char *iface = argv[1];
    uint32_t can_id = (uint32_t)strtoul(argv[2], NULL, 16);
    uint32_t freshness_counter = (uint32_t)strtoul(argv[3], NULL, 10);
 
    unsigned char payload[AUTHENTIC_PAYLOAD_LEN] = AUTHENTIC_PAYLOAD;
 
    /* Full freshness value, big-endian, padded/truncated to FRESHNESS_FULL_LEN */
    unsigned char freshness_full[FRESHNESS_FULL_LEN];
    for (int i = 0; i < FRESHNESS_FULL_LEN; i++) {
        int shift = 8 * (FRESHNESS_FULL_LEN - 1 - i);
        freshness_full[i] = (shift < 32) ? (unsigned char)((freshness_counter >> shift) & 0xFF) : 0;
    }
 
    /* Build MAC input and compute CMAC */
    unsigned char mac_input[2 + FRESHNESS_FULL_LEN + AUTHENTIC_PAYLOAD_LEN];
    size_t mac_input_len = build_mac_input(mac_input, DATA_ID,
                                            freshness_full, FRESHNESS_FULL_LEN,
                                            payload, AUTHENTIC_PAYLOAD_LEN);
 
    unsigned char mac_full[EVP_MAX_MD_SIZE];
    size_t mac_full_len = 0;
    if (compute_cmac(secoc_key, sizeof(secoc_key),
                      mac_input, mac_input_len,
                      mac_full, &mac_full_len) != 0) {
        fprintf(stderr, "CMAC computation failed\n");
        return 1;
    }
    if (mac_full_len < MAC_TX_LEN) {
        fprintf(stderr, "MAC shorter than requested truncation length\n");
        return 1;
    }
 
    /* Assemble final SecOC PDU: payload || truncated freshness || truncated MAC */
    unsigned char pdu[64];
    size_t pdu_len = 0;
 
    memcpy(pdu + pdu_len, payload, AUTHENTIC_PAYLOAD_LEN);
    pdu_len += AUTHENTIC_PAYLOAD_LEN;
 
    /* transmit only the low-order FRESHNESS_TX_LEN bytes of freshness */
    memcpy(pdu + pdu_len,
           freshness_full + (FRESHNESS_FULL_LEN - FRESHNESS_TX_LEN),
           FRESHNESS_TX_LEN);
    pdu_len += FRESHNESS_TX_LEN;
 
    memcpy(pdu + pdu_len, mac_full, MAC_TX_LEN);
    pdu_len += MAC_TX_LEN;
 
    if (pdu_len > 64) {
        fprintf(stderr, "assembled PDU exceeds CAN FD max payload (64 bytes)\n");
        return 1;
    }
 
    /* ---- Send over SocketCAN as a CAN FD frame ---- */
 
    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
 
    /* enable CAN FD frames on this socket */
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
 
    struct canfd_frame frame;
    memset(&frame, 0, sizeof(frame));
    frame.can_id = can_id;
    frame.len = (uint8_t)pdu_len;
    frame.flags = CANFD_BRS; /* bit rate switch; clear if your bus doesn't use it */
    memcpy(frame.data, pdu, pdu_len);
 
    ssize_t nbytes = write(sock, &frame, sizeof(struct canfd_frame));
    if (nbytes != sizeof(struct canfd_frame)) {
        perror("write");
        close(sock);
        return 1;
    }
 
    printf("Sent SecOC frame on %s: id=0x%03X len=%zu freshness_ctr=%u\n",
           iface, can_id, pdu_len, freshness_counter);
    printf("  payload   : ");
    for (int i = 0; i < AUTHENTIC_PAYLOAD_LEN; i++) printf("%02X ", payload[i]);
    printf("\n  freshness : ");
    for (int i = 0; i < FRESHNESS_TX_LEN; i++)
        printf("%02X ", pdu[AUTHENTIC_PAYLOAD_LEN + i]);
    printf("\n  mac(trunc): ");
    for (int i = 0; i < MAC_TX_LEN; i++)
        printf("%02X ", pdu[AUTHENTIC_PAYLOAD_LEN + FRESHNESS_TX_LEN + i]);
    printf("\n");
 
    close(sock);
    return 0;
}
