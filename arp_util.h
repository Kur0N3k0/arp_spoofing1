#ifndef __ARP_UTIL_H__
#define __ARP_UTIL_H__

#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

#include "arp_header.h"

using namespace std;

/*
 * Function Implements
*/

void getmac(const char *byte);
void getMyMAC(const char *dev, uint8_t *mac);
void getMyIP(const char *dev, uint8_t *ip);
void getIPfromMAC(pcap_t *handle, const char *dev, uint8_t *targetip, uint8_t *targetmac);
void ARPSend(pcap_t *handle, const char *dev, uint16_t oper, uint8_t *senderip, uint8_t *sendermac, uint8_t *targetip, uint8_t *targetmac);
void ARPInfect(pcap_t *handle, const char *dev, uint16_t oper, uint8_t *ip, uint8_t *mac, uint8_t *ip2, uint8_t *mac2);
void printPacket(ethernet *ether);

#endif