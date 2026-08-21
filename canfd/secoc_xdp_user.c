/* SPDX-License-Identifier: MIT
 *
 * secoc_xdp_user.c
 *
 * Loads secoc_xdp.o onto an interface, then services the ring buffer:
 * for each candidate frame that passed the in-kernel fast checks
 * (length + freshness anti-replay), recompute the CMAC and verify it.
 * On success, commit the frame's freshness value into the BPF hash map
 * so the kernel-side anti-replay check advances; on failure, do
 * nothing (the stale/bad value is simply never committed).
 *
 * This must be built and linked against the compiled secoc_xdp.o via
 * libbpf. Simplified here to use plain libbpf calls (no skeleton
 * codegen) so it only depends on libbpf + libelf + libcrypto.
 *
 * Build (adjust libbpf include/lib paths for your system):
 *   clang -O2 -g -target bpf -c secoc_xdp.c -o secoc_xdp.o
 *   gcc -O2 -Wall secoc_xdp_user.c -o secoc_xdp_user -lbpf -lelf -lcrypto
 *
 * Usage:
 *   sudo ./secoc_xdp_user <iface>
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <signal.h>
 #include <unistd.h>
 #include <net/if.h>
 #include <errno.h>
 
 #include <bpf/libbpf.h>
 #include <bpf/bpf.h>
 
 #include <openssl/cmac.h>
 #include <openssl/evp.h>
 
 /* ---- MUST MATCH secoc_send.c / secoc_recv.c / secoc_xdp.c ---- */
 #define DATA_ID               0x1234u
 #define AUTHENTIC_PAYLOAD_LEN 8
 #define FRESHNESS_FULL_LEN    4
 #define FRESHNESS_TX_LEN      2
 #define MAC_TX_LEN            4
 
 static const unsigned char secoc_key[16] = {
     0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
 };
 
 struct secoc_candidate {
     uint32_t can_id;
     uint8_t  len;
     uint8_t  data[64];
 };
 
 static volatile sig_atomic_t stop;
 static void on_sigint(int sig) { (void)sig; stop = 1; }
 
 static size_t build_mac_input(unsigned char *out, uint16_t data_id,
                                const unsigned char *freshness_full, size_t fl,
                                const unsigned char *payload, size_t pl)
 {
     size_t off = 0;
     out[off++] = (data_id >> 8) & 0xFF;
     out[off++] = data_id & 0xFF;
     memcpy(out + off, freshness_full, fl); off += fl;
     memcpy(out + off, payload, pl); off += pl;
     return off;
 }
 
 static int compute_cmac(const unsigned char *key, size_t key_len,
                          const unsigned char *msg, size_t msg_len,
                          unsigned char *mac_out, size_t *mac_out_len)
 {
     CMAC_CTX *ctx = CMAC_CTX_new();
     if (!ctx) return -1;
     if (!CMAC_Init(ctx, key, key_len, EVP_aes_128_cbc(), NULL) ||
         !CMAC_Update(ctx, msg, msg_len) ||
         !CMAC_Final(ctx, mac_out, mac_out_len)) {
         CMAC_CTX_free(ctx);
         return -1;
     }
     CMAC_CTX_free(ctx);
     return 0;
 }
 
 /* freshness map fd, set in main() before ring_buffer__poll runs */
 static int freshness_map_fd = -1;
 
 static int handle_event(void *ctx, void *data, size_t data_sz)
 {
     (void)ctx;
     if (data_sz < sizeof(struct secoc_candidate))
         return 0;
 
     const struct secoc_candidate *c = data;
 
     if (c->len < AUTHENTIC_PAYLOAD_LEN + FRESHNESS_TX_LEN + MAC_TX_LEN)
         return 0; /* shouldn't happen, kernel side already checked */
 
     const uint8_t *payload      = c->data;
     const uint8_t *freshness_tx = c->data + AUTHENTIC_PAYLOAD_LEN;
     const uint8_t *mac_tx       = c->data + AUTHENTIC_PAYLOAD_LEN + FRESHNESS_TX_LEN;
 
     /* Reconstruct full freshness value. For simplicity, zero-extend the
      * truncated value (matches secoc_send.c's send-from-zero test flow).
      * A production implementation should reconstruct against the last
      * known full value the same way secoc_recv.c does. */
     uint32_t freshness_val = 0;
     for (int i = 0; i < FRESHNESS_TX_LEN; i++)
         freshness_val = (freshness_val << 8) | freshness_tx[i];
 
     unsigned char freshness_full[FRESHNESS_FULL_LEN];
     for (int i = 0; i < FRESHNESS_FULL_LEN; i++) {
         int shift = 8 * (FRESHNESS_FULL_LEN - 1 - i);
         freshness_full[i] = (shift < 32) ? (unsigned char)((freshness_val >> shift) & 0xFF) : 0;
     }
 
     unsigned char mac_input[2 + FRESHNESS_FULL_LEN + AUTHENTIC_PAYLOAD_LEN];
     size_t mac_input_len = build_mac_input(mac_input, DATA_ID,
                                             freshness_full, FRESHNESS_FULL_LEN,
                                             payload, AUTHENTIC_PAYLOAD_LEN);
 
     unsigned char mac_full[EVP_MAX_MD_SIZE];
     size_t mac_full_len = 0;
     int mac_ok = 0;
     if (compute_cmac(secoc_key, sizeof(secoc_key), mac_input, mac_input_len,
                       mac_full, &mac_full_len) == 0 &&
         mac_full_len >= MAC_TX_LEN) {
         mac_ok = (memcmp(mac_full, mac_tx, MAC_TX_LEN) == 0);
     }
 
     printf("[id=0x%03X] freshness=%u mac=%s -> %s\n",
            c->can_id, freshness_val, mac_ok ? "OK" : "FAIL",
            mac_ok ? "ACCEPT" : "REJECT");
 
     if (mac_ok && freshness_map_fd >= 0) {
         /* Commit freshness so the kernel-side anti-replay check advances */
         bpf_map_update_elem(freshness_map_fd, &c->can_id, &freshness_val, BPF_ANY);
     }
 
     return 0;
 }
 
 int main(int argc, char **argv)
 {
     if (argc != 2) {
         fprintf(stderr, "usage: %s <iface>\n", argv[0]);
         return 1;
     }
 
     const char *iface = argv[1];
     int ifindex = if_nametoindex(iface);
     if (!ifindex) {
         fprintf(stderr, "unknown interface %s\n", iface);
         return 1;
     }
 
     struct bpf_object *obj = bpf_object__open_file("secoc_xdp.o", NULL);
     if (libbpf_get_error(obj)) {
         fprintf(stderr, "failed to open secoc_xdp.o\n");
         return 1;
     }
     if (bpf_object__load(obj)) {
         fprintf(stderr, "failed to load BPF object\n");
         return 1;
     }
 
     struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_secoc_check");
     if (!prog) {
         fprintf(stderr, "program xdp_secoc_check not found\n");
         return 1;
     }
     int prog_fd = bpf_program__fd(prog);
 
     if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL) < 0) {
         fprintf(stderr, "failed to attach XDP program to %s\n", iface);
         return 1;
     }
     printf("Attached SecOC XDP fast-path checker to %s\n", iface);
 
     struct bpf_map *freshness_map = bpf_object__find_map_by_name(obj, "secoc_freshness");
     struct bpf_map *events_map    = bpf_object__find_map_by_name(obj, "secoc_events");
     if (!freshness_map || !events_map) {
         fprintf(stderr, "expected maps not found in object\n");
         bpf_xdp_detach(ifindex, 0, NULL);
         return 1;
     }
     freshness_map_fd = bpf_map__fd(freshness_map);
     int events_fd = bpf_map__fd(events_map);
 
     struct ring_buffer *rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
     if (!rb) {
         fprintf(stderr, "failed to create ring buffer\n");
         bpf_xdp_detach(ifindex, 0, NULL);
         return 1;
     }
 
     signal(SIGINT, on_sigint);
     signal(SIGTERM, on_sigint);
 
     printf("Servicing ring buffer (Ctrl+C to stop and unload)...\n");
     while (!stop) {
         int err = ring_buffer__poll(rb, 100 /* ms */);
         if (err < 0 && err != -EINTR) {
             fprintf(stderr, "ring_buffer__poll error: %d\n", err);
             break;
         }
     }
 
     printf("\nDetaching and cleaning up...\n");
     ring_buffer__free(rb);
     bpf_xdp_detach(ifindex, 0, NULL);
     bpf_object__close(obj);
 
     return 0;
 }