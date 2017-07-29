all : arp_comp

arp_comp : 
	gcc -o arp arp.c -lpcap

clean :
	rm -f arp
