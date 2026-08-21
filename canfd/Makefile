.PHONY: clean all

secoc_xdp.o: secoc_xdp.c 
	clang -O2 -g -target bpf -c secoc_xdp.c -o secoc_xdp.o

secoc_xdp_user: secoc_xdp_user.c secoc_xdp.o
	gcc -O2 -Wall secoc_xdp_user.c -o secoc_xdp_user -lbpf -lelf -lcrypto

secoc_send: secoc_send.c
	gcc -O2 -Wall secoc_send.c -o secoc_send -lcrypto

secoc_recv: secoc_recv.c
	gcc -O2 -Wall secoc_recv.c -o secoc_recv -lcrypto

xdp_canfd_check.o: xdp_canfd_check.c
	clang -O2 -g -target bpf -c xdp_canfd_check.c -o xdp_canfd_check.o

clean: 
	rm secoc_xdp.o secoc_xdp_user secoc_send secoc_recv xdp_canfd_check.o

all: secoc_send secoc_recv xdp_canfd_check secoc_xdp.o secoc_xdp_user xdp_canfd_check.o
