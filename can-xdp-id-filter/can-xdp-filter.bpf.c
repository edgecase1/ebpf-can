
/*

*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct can_frame {
        __u32   can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
        __u8    can_dlc; /* data length code: 0 .. 8 */
        __u8    data[8] __attribute__((aligned(8)));
};

struct inner_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);  // can_id u32
    __type(value, __u32); // XDP_BLOCK, XDP_PASS 
} xdp_can_ids_map SEC(".maps");

SEC("xdp")
int xdp_filter_can(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct can_frame *frame = data;
    __u32 can_id = 0;
    __u32 value;
    void *ret;

    if(data + sizeof(struct can_frame) > data_end)
    {
        bpf_printk("drop");
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

    can_id = frame->can_id;
    //if(frame->can_id == 0x111) // firewall 0x111 packets
    //    return XDP_PASS;
    ret = bpf_map_lookup_elem(&xdp_can_ids_map, &can_id);
    bpf_printk("ID %x %d = %d", can_id, can_id, ret);
    if(ret < 0)
	return XDP_DROP;

    bpf_probe_read_kernel(&value, sizeof(__u32), ret);
    if(value == 1)
        return XDP_PASS;

    // default block
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
