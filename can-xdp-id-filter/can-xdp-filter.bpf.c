
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 255);
    __type(key, __u32);  // can_id u32
    __type(value, __u32); // action XDP_BLOCK, XDP_PASS 
} xdp_can_ids_map SEC(".maps");

static bool check_dlc(__u8 can_dlc)
{
    if(can_dlc <= 3)
    {
    	return true;
    }
    else 
    {
	return false;
    }
}

static bool check_crc(__u8 can_data[])
{
    if(can_data[3] == 0x44)
    {
        return true;	   
    }

    return false;
}

SEC("xdp")
int xdp_filter_can(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct can_frame *frame = data;
    __u32 can_id = 0;
    __u32 opmode;
    void *ret;
    __u8 can_data[8];

    if(data + sizeof(struct can_frame) > data_end)
    {
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

    // look up can_id in map
    ret = bpf_map_lookup_elem(&xdp_can_ids_map, &can_id);
    if(!ret) // can_id not found in the map
    {
	// look up the default behavior
        can_id = 0; // default ID
        ret = bpf_map_lookup_elem(&xdp_can_ids_map, &can_id);
        if(!ret) // user didn't set the default 
            return XDP_DROP;

        bpf_probe_read_kernel(&opmode, sizeof(__u32), ret);
        if(opmode == 2)
        {
    	    return XDP_PASS;
        } else {
            return XDP_DROP;
        }
    } else {
	// can_id exists in map
        bpf_probe_read_kernel(&opmode, sizeof(__u32), ret);
        switch(opmode) {
            case 0: // XDP_ABORTED
            case 1: // XDP_DROP
            case 2: // XDP_DROP
                return XDP_DROP;
            case 3: // XDP_PASS
            case 4: // XDP_TX
            case 5: // XDP_REDIRECT
                return XDP_PASS;
            case 6: // LEN
                if(check_dlc(frame->can_dlc))
                {
                    return XDP_PASS;
                } else {
            	return XDP_DROP;
                }
                break;
            case 7: // CRC
        	bpf_probe_read_kernel(&can_data, 8, frame->data);
                if(check_crc(can_data))
                {
                    return XDP_PASS;		   
                } else {
            	    return XDP_DROP;
                }
            default:
                return XDP_DROP;
        }
    }

    return XDP_DROP; // catch all
}

char _license[] SEC("license") = "GPL";
