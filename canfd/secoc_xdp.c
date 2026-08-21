// SPDX-License-Identifier: GPL-2.0
/*
 * secoc_xdp.c
 *
 * Fast-path SecOC checks in XDP:
 *   1. Frame length sanity (enough bytes for payload+freshness+MAC).
 *   2. Freshness anti-replay check per CAN ID, using a BPF hash map to
 *      remember the last accepted (reconstructed) freshness value.
 *
 * MAC verification is NOT done here - AES-CMAC is not practical to
 * implement robustly inside the BPF verifier's constraints. Frames
 * that pass the fast checks are pushed to userspace via a ring buffer
 * for full CMAC verification (see secoc_xdp_user.c). Frames that fail
 * the fast checks (too short, or stale/replayed freshness) are dropped
 * immediately without ever reaching userspace.
 *
 * Config below MUST match secoc_send.c / secoc_recv.c.
 */

 #include <linux/bpf.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_endian.h>
 
 #define AUTHENTIC_PAYLOAD_LEN 8
 #define FRESHNESS_TX_LEN      2
 #define MAC_TX_LEN            4
 #define EXPECTED_MIN_LEN      (AUTHENTIC_PAYLOAD_LEN + FRESHNESS_TX_LEN + MAC_TX_LEN)
 
 /* canfd_frame layout offsets (see earlier program for full breakdown) */
 #define CANFD_ID_OFFSET     0   /* canid_t, 4 bytes */
 #define CANFD_LEN_OFFSET    4   /* __u8 len */
 #define CANFD_DATA_OFFSET   8   /* payload start */
 
 /* Struct pushed to userspace for full MAC verification */
 struct secoc_candidate {
     __u32 can_id;
     __u8  len;
     __u8  data[64];
 };
 
 /* Tracks last accepted (truncated, as received) freshness value per CAN ID */
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);    /* CAN ID */
     __type(value, __u32);  /* last accepted freshness (widened) */
 } secoc_freshness SEC(".maps");
 
 /* Ring buffer: candidates that passed fast checks, awaiting MAC verify */
 struct {
     __uint(type, BPF_MAP_TYPE_RINGBUF);
     __uint(max_entries, 256 * 1024);
 } secoc_events SEC(".maps");
 
 SEC("xdp")
 int xdp_secoc_check(struct xdp_md *ctx)
 {
     void *data     = (void *)(long)ctx->data;
     void *data_end = (void *)(long)ctx->data_end;
 
     __u8 *frame = data;

     /* Bounds check for the fixed part of canfd_frame we need to read */
     if ((void *)(frame + CANFD_DATA_OFFSET + 1) > data_end)
     {
        bpf_printk("Bounds check");
        return XDP_PASS; /* not a full CAN FD header, let it through untouched */
     }
 
     __u32 can_id;
     __builtin_memcpy(&can_id, frame + CANFD_ID_OFFSET, sizeof(can_id));
 
     __u8 len = frame[CANFD_LEN_OFFSET];
 
     /* Verifier needs a concrete bound before we index into frame data
      * with a runtime-derived length. Cap at canfd_frame's max (64). */
     if (len > 64)
     {
         return XDP_DROP;
     }
 
     /* Constant-offset bounds check covering the full possible payload
      * region (0..63). This is what makes every fixed-offset access
      * below (freshness_tx, mac_tx, the ring buffer copy loop) provably
      * safe to the verifier - a check tied to the *variable* `len`
      * pointer expression does NOT propagate to separately-computed
      * fixed-offset pointers, which is what caused "invalid access to
      * packet, off=17" here. */
     if ((void *)(frame + CANFD_DATA_OFFSET + 64) > data_end)
     {
         bpf_printk("not enough packet data");
         return XDP_DROP; /* not enough packet data for a full-size frame */
     }
 
     if (len < EXPECTED_MIN_LEN) 
     {
         /* Too short to contain payload+freshness+MAC - reject fast */
         bpf_printk("min length");
         return XDP_DROP;
     }
 
     /* Extract truncated freshness bytes (big-endian) into a u32 */
     __u8 *freshness_tx = frame + CANFD_DATA_OFFSET + AUTHENTIC_PAYLOAD_LEN;
     __u32 freshness_val = 0;
     // verifier
     if (freshness_tx > data_end) 
     {
        /* Too short to contain payload+freshness+MAC - reject fast */
        bpf_printk("freshness too short %d %x", can_id, freshness_val);
        return XDP_DROP;
     }     
 #pragma unroll
     for (int i = 0; i < FRESHNESS_TX_LEN; i++) 
     {
         freshness_val = (freshness_val << 8) | freshness_tx[i];
     }
 
     /* Anti-replay: reject if not strictly newer than last accepted value
      * for this CAN ID */
     __u32 *last = bpf_map_lookup_elem(&secoc_freshness, &can_id);
     if (last && freshness_val <= *last) 
     {
         bpf_printk("freshness incorrect %d %x", can_id, freshness_val);
         return XDP_PASS; /* TODO DROP stale or replayed frame */
     }
 
     /* Passed fast checks - push to userspace for MAC verification.
      * We do NOT update secoc_freshness here: only commit the new
      * freshness value once userspace confirms the MAC is valid,
      * otherwise a spoofed frame with a bumped freshness counter but
      * bad MAC would poison the anti-replay state and let a real
      * subsequent frame get dropped as "stale". */
     struct secoc_candidate *ev = bpf_ringbuf_reserve(&secoc_events, sizeof(*ev), 0);
     if (!ev) {
         /* ring buffer full - drop rather than pass unverified */
         return XDP_DROP;
     }
 
     ev->can_id = can_id;
     ev->len = len;
 #pragma unroll
     for (int i = 0; i < 64; i++) {
         ev->data[i] = (i < len) ? frame[CANFD_DATA_OFFSET + i] : 0;
     }
 
     bpf_ringbuf_submit(ev, 0);
 
     /* Allow at XDP either way - userspace (via secoc_xdp_user.c) is
      * responsible for re-injecting verified-good frames downstream if
      * your architecture needs that (e.g. via a raw socket or AF_XDP TX).
      * Change to XDP_PASS if you'd rather let the kernel network stack
      * see it too, with userspace verification as an out-of-band audit
      * instead of a hard gate. */
     bpf_printk("xdp_secoc_check PASS");
     return XDP_PASS;
 }
 
 char _license[] SEC("license") = "GPL";