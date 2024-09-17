
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct can_frame {
        __u32   can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
        __u8    can_dlc; /* data length code: 0 .. 8 */
        __u8    data[8] __attribute__((aligned(8)));
};

SEC("xdp")
int xdp_can_drop_id0x123(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct can_frame *frame = data;

    if(data + sizeof(struct can_frame) > data_end) // for verifier
    {
        bpf_printk("dropping CAN frame because of verifier.");
        return XDP_DROP;
    }

    bpf_printk("can/xdp id=0x%x dlc=%d data=0x%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x\n", 
        frame->can_id, 
        frame->can_dlc, 
        frame->data[0],
        frame->data[1],
        frame->data[2],
        frame->data[3],
        frame->data[4],
        frame->data[5],
        frame->data[6],
        frame->data[7]); // 8 data bytes

    if(frame->can_id == 0x123) // drop CAN frames with CAN ID 0x123 packets
    {			 
        bpf_printk("dropping CAN frame with ID 0x123.");
        return XDP_DROP;
    }

    // default action
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
