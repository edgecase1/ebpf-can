#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7

struct can_frame {
        __u32   can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
        __u8    can_dlc; /* data length code: 0 .. 8 */
        __u8    data[8] __attribute__((aligned(8)));
};

SEC("tc/ingress")
int tc_length_limit(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct can_frame *frame = data;

    if(data + sizeof(struct can_frame) > data_end)
    {
        return TC_ACT_SHOT;
    }

    // output the current CAN frame
    bpf_printk("can id=0x%x dlc=%d data=%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x\n", 
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

    if(frame->can_dlc >= 5)
    { 
    	return TC_ACT_SHOT; 
    }

    return TC_ACT_OK; 
}

char _license[] SEC("license") = "GPL";
