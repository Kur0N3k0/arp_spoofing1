#ifndef __ARP_HEADER_H__
#define __ARP_HEADER_H__

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

typedef struct ip{
	uint8_t hdr_len:4;
	uint8_t version:4;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint8_t ip_frag_offset:5;
	uint8_t ip_more_fragment:1;
	uint8_t ip_dont_fragment:1;
	uint8_t ip_reserved_zero:1;
	uint8_t ip_frag_offset1;
	uint8_t ip_ttl;
	uint8_t ip_protocol;
	uint16_t ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
} ip;

typedef struct tcp{
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t sequence;
	uint32_t acknowledge;
	uint8_t ns:1;
	uint8_t reserved_part1:3;
	uint8_t data_offset:4;
	uint8_t fin:1;
	uint8_t syn:1;
	uint8_t rst:1;
	uint8_t psh:1;
	uint8_t ack:1;
	uint8_t urg:1;
	uint8_t ecn:1;
	uint8_t cwr:1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} tcp;

#define ARP_REQUEST	1
#define ARP_REPLY	2

#define MAC_SIZE	6

typedef struct arp_packet {
	ethernet ether;
	arphdr_t arp;
} arp_packet;

#endif