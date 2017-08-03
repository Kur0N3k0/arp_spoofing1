all : arp_comp

arp_comp : arp_util arp_info
	g++ -o arp arp.cpp arp_util.o arp_info.o -lpcap -pthread -std=c++11

arp_util :
	g++ -c arp_util.cpp -lpcap

arp_info :
	g++ -c arp_info.cpp -lpcap -pthread -std=c++11

clean :
	rm -f arp *.o