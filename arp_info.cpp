#include "arp_info.h"

Info::~Info(){
	pthread_cancel(spoofing->native_handle());
	delete spoofing;
}

uint8_t *Info::getSender_ip() const {
	return (uint8_t *)sender_ip;
}

uint8_t *Info::getTarget_ip() const {
	return (uint8_t *)target_ip;
}

uint8_t *Info::getMymac() const {
	return (uint8_t *)mymac;
}

uint8_t *Info::getSender_mac() const {
	return (uint8_t *)sender_mac;
}

uint8_t *Info::getTarget_mac() const {
	return (uint8_t *)target_mac;
}

thread *Info::getSpoofing() const {
	return spoofing;
}

void Info::setSender_ip(uint8_t *sender_ip) {
	memcpy(this->sender_ip, sender_ip, INET_ADDRSTRLEN);
}

void Info::setTarget_ip(uint8_t *target_ip) {
	memcpy(this->target_ip, target_ip, INET_ADDRSTRLEN);
}

void Info::setMymac(uint8_t *mymac) {
	memcpy(this->mymac, mymac, MAC_SIZE);
}

void Info::setSender_mac(uint8_t *sender_mac) {
	memcpy(this->sender_mac, sender_mac, MAC_SIZE);
}

void Info::setTarget_mac(uint8_t *target_mac) {
	memcpy(this->target_mac, target_mac, MAC_SIZE);
}

void Info::setSpoofing(thread *spoofing) {
	this->spoofing = spoofing;
}