┌──(kali㉿kali)-[~/ebpf-can/can-xdp-id-filter]
└─$ sudo bpftool map update name xdp_can_ids_map key 0x23 0x1 0x0 0x0 value 1
                                                                                                                                                      
┌──(kali㉿kali)-[~/ebpf-can/can-xdp-id-filter]
└─$ sudo bpftool map dump name xdp_can_ids_map | grep -B 5 -A 5 291      
