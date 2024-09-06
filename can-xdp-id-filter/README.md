This project implements a CAN 2.0 firewall in eBPF code. The eBPF program attaches to XDP of a CAN interface, inspects the CAN packets and DROPs or PASSes the frames based on the configuration. The decision is made based on the frame's arbitration ID, data payload and data length extension. The mode of operation is set in an eBPF map for the filter program.
The filter program is loaded and attached to an interface using the ``load.sh``-script. The script can also handle the attachment to a container interface.

Current limitations are that the filter program only process CAN 2.0 frames. CAN FD or CAN XL is not supported.

= Modes of operation =
The mode of operation (opmode) is stored to an eBPF map in the format <CAN ID>:<opmode>. The default mode of operation is BLOCK and can be changed to PASS writing a 0:2 in the eBPF map `xdp_can_ids_map`.

Pass mode: passes all CAN frames on this interface.
`sudo bpftool map update name xdp_can_ids_map key 0 0 0 0 value 2 0 0 0`
Reset to Block mode: drops all CAN frames on this interface.
`sudo bpftool map update name xdp_can_ids_map key 0 0 0 0 value 0 0 0 0`

== CAN ID specific actions ==
All the following examples are actions applied to all CAN frames with arbitration ID 0x123. 

Block CAN frames with CAN ID 0x123 on the interface.
`sudo bpftool map update name xdp_can_ids_map key 0x23 0x1 0x0 0x0 value 2`

Pass mode: allows all CAN frames with CAN ID 0x123 on this interface.
`sudo bpftool map update name xdp_can_ids_map key 0x23 0x1 0x0 0x0 value 3`

Limit length mode: allows only CAN frames with a specific length and CAN ID 0x123 PASS on this interface.
`sudo bpftool map update name xdp_can_ids_map key 0x23 0x1 0x0 0x0 value 6`

Format check mode: only packets with 44 in the third byte and CAN ID 0x123 are PASSed on the interface. 
`sudo bpftool map update name xdp_can_ids_map key 0x23 0x1 0x0 0x0 value 7`

= Debugging =
Show current map
`sudo bpftool map dump name xdp_can_ids_map`

Show trace pipe with CAN Ids and data
`sudo cat /sys/kernel/debug/tracing/trace_pipe`
