
lengthlimit.bpf.o: lengthlimit.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c lengthlimit.bpf.c -o lengthlimit.bpf.o 

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

