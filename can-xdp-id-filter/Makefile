.PHONY: all

all: can-xdp-filter.bpf.o

can-xdp-filter.bpf.o: can-xdp-filter.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c can-xdp-filter.bpf.c -o can-xdp-filter.bpf.o 

canxdpfw: 
	echo "not implemented"	

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

