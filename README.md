
## XDP vcan0

```
sudo bash setup_vcan.sh
ip link show vcan0
16: vcan0: <NOARP,UP,LOWER_UP> mtu 72 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/can

pushd can-xdp ; make ; popd
~/can-ebpf-rpi4-tests/can-xdp ~/can-ebpf-rpi4-tests
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h.tmp
mv vmlinux.h.tmp vmlinux.h
clang -g -O2 -Wall -target bpf -I . -c can-xdp.bpf.c -o can-xdp.bpf.o
clang -g -O2 -Wall -target bpf -I . -c can-xdp.bpf_1000dropid.c -o can-xdp.bpf_1000dropid.o
clang -g -O2 -Wall -target bpf -I . -c can-xdp.bpf_100dropid.bpf.c -o can-xdp.bpf_100dropid.bpf.o
~/can-ebpf-rpi4-tests

sudo ip link set dev vcan0 xdp obj ./can-xdp/can-xdp.bpf.o sec xdp
ip link show vcan0
16: vcan0: <NOARP,UP,LOWER_UP> mtu 72 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/can
    prog/xdp id 375
```
