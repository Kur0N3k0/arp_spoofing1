#ifndef __ARP_INFO_H__
#define __ARP_INFO_H__

#include <iostream>
#include <thread>

#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <pthread.h>

#include "arp_header.h"

using namespace std;

class Info {
private:
	uint8_t sender_ip[INET_ADDRSTRLEN];
	uint8_t target_ip[INET_ADDRSTRLEN];
	uint8_t mymac[MAC_SIZE];
	uint8_t sender_mac[MAC_SIZE];
	uint8_t target_mac[MAC_SIZE];

	thread *spoofing;
public:
	~Info();

	uint8_t *getSender_ip() const;
	uint8_t *getTarget_ip() const;
	uint8_t *getMymac() const;
	uint8_t *getSender_mac() const;
	uint8_t *getTarget_mac() const;
	thread *getSpoofing() const;

	void setSender_ip(uint8_t *sender_ip);
	void setTarget_ip(uint8_t *target_ip);
	void setMymac(uint8_t *mymac);
	void setSender_mac(uint8_t *sender_mac);
	void setTarget_mac(uint8_t *target_mac);
	void setSpoofing(thread *spoofing);
};

#endif