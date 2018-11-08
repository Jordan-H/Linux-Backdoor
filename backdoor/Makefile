
# Makefile for pkt_sniffer

CC=gcc -g
CLIB=-lpcap

pkt_sniffer: backdoor.o proc_ether.o proc_hdrs.o proc_payload.o
	$(CC) -o backdoor backdoor.o proc_ether.o proc_hdrs.o proc_payload.o $(CLIB)

clean:
	rm -f *.o core backdoor

backdoor.o:
	$(CC) -c backdoor.c

proc_ether.o:
	$(CC) -c proc_ether.c

proc_hdrs.o:
	$(CC) -c proc_hdrs.c
proc_payload.o:
	$(CC) -c proc_payload.c
