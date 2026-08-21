// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_canfd_check.c
 *
 * XDP program that inspects incoming CAN FD frames and checks whether
 * the 12th byte (1-indexed) of the frame equals 0x42.
 *
 * CAN FD frame layout (struct canfd_frame, linux/can.h):
 *
 *   offset 0-3  : canid_t can_id   (4 bytes)
 *   offset 4    : __u8   len       (1 byte)
 *   offset 5    : __u8   flags     (1 byte)
 *   offset 6    : __u8   __res0    (1 byte)
 *   offset 7    : __u8   __res1    (1 byte)
 *   offset 8-71 : __u8   data[64]  (payload)
 *
 * => "12th byte" (1-indexed) = offset 11 = data[3].
 *
 * If your pipeline prepends anything before the raw canfd_frame bytes
 * (e.g. an Ethernet header when CAN traffic is tunnelled), adjust
 * FRAME_START_OFFSET accordingly.
 */

 #include <linux/bpf.h>
 #include <bpf/bpf_helpers.h>
 
 /* Offset, in bytes, from the start of ctx->data to the start of the
  * canfd_frame struct. 0 if XDP sees the raw CAN frame directly. */
 #define FRAME_START_OFFSET  0
 
 /* 12th byte, 0-indexed -> offset 11 within the frame */
 #define TARGET_BYTE_OFFSET  11
 #define TARGET_BYTE_VALUE   0x42
 
 SEC("xdp")
 int xdp_canfd_check(struct xdp_md *ctx)
 {
     void *data     = (void *)(long)ctx->data;
     void *data_end = (void *)(long)ctx->data_end;
 
     __u8 *frame = (__u8 *)data + FRAME_START_OFFSET;
 
     /* Mandatory eBPF verifier bounds check before touching packet memory */
     if ((void *)(frame + TARGET_BYTE_OFFSET + 1) > data_end)
         return XDP_PASS;
 
     __u8 byte12 = frame[TARGET_BYTE_OFFSET];
 
     if (byte12 == TARGET_BYTE_VALUE) {
         bpf_printk("xdp_canfd_check: byte[12] matched 0x%x\n", byte12);
         /* Swap XDP_PASS for XDP_DROP / XDP_TX / a redirect as needed */
         return XDP_PASS;
     }
 
     return XDP_PASS;
 }
 
 char _license[] SEC("license") = "GPL";