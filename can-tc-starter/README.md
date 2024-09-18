
This example attaches an eBPF program that limits the length of the CAN frame by data length code (can\_dlc).

The subsequent `candump` output of a `cangen vcan0` call would display only the permitted CAN frames.
The other CAN frames are dropped by the Kernel in the traffic control processing.
```
  vcan0  119   [1]  CA
  vcan0  026   [0] 
  vcan0  4F1   [1]  E4
  vcan0  089   [2]  1A A0
  vcan0  2D4   [4]  1E E3 6C 59
  vcan0  0F5   [4]  96 13 6F 14
  vcan0  1C5   [0] 
  vcan0  339   [1]  5B
  vcan0  167   [3]  64 8A A7
  vcan0  25B   [1]  B9
  vcan0  313   [3]  E9 A0 98
  vcan0  165   [3]  17 05 F6
  vcan0  297   [0] 
```
For debugging purposes all received CAN frames are displayed on the trace\_pipe:

```
# cat /sys/kernel/tracing/trace_pipe

  cangen-125643  [000] ..s2. 15139.422768: bpf_trace_printk: can id=0x614 dlc=8 data=65.11.97.18.fc.21.1e.6a
  cangen-125643  [000] ..s2. 15139.623994: bpf_trace_printk: can id=0x52a dlc=8 data=59.6a.b6.41.f6.04.a2.1a
  cangen-125643  [000] ..s2. 15139.824958: bpf_trace_printk: can id=0x7ff dlc=8 data=f2.b9.dc.14.f5.7e.30.6e
  cangen-125643  [000] ..s2. 15140.025715: bpf_trace_printk: can id=0x104 dlc=8 data=4c.fc.ca.27.1f.aa.fc.77
  cangen-125643  [000] ..s2. 15140.227031: bpf_trace_printk: can id=0x4fd dlc=8 data=db.df.23.45.79.1f.57.2d
  cangen-125643  [000] ..s2. 15140.428594: bpf_trace_printk: can id=0x340 dlc=6 data=62.80.2b.30.64.d7.00.00
  cangen-125643  [000] ..s2. 15140.629774: bpf_trace_printk: can id=0x1e1 dlc=8 data=c7.f8.7f.4f.3f.05.ce.73
  cangen-125643  [000] ..s2. 15140.831315: bpf_trace_printk: can id=0x653 dlc=5 data=be.25.bb.25.68.00.00.00
  cangen-125643  [000] ..s2. 15141.032339: bpf_trace_printk: can id=0x3a4 dlc=3 data=64.7e.24.00.00.00.00.00
  cangen-125643  [000] ..s2. 15141.233207: bpf_trace_printk: can id=0xf1 dlc=8 data=c5.8d.0c.52.f0.e8.51.0d
```
This shows that the Kernel only accepts specific packets and the userspace application will not receive the dropped CAN frames via `socket CAN`.
