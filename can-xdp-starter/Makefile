
can-xdp.bpf.o: can-xdp.bpf.o vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c can-xdp.bpf.c -o can-xdp.bpf.o 

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

