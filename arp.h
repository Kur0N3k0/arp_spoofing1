#ifndef __ARP_H__
#define __ARP_H__

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

#include <signal.h> // signal handling SIGINT

#include "arp_header.h" // structure
#include "arp_util.h" // function implements
#include "arp_info.h" // info class

#endif