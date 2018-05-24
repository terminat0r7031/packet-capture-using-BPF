#ifndef PROCESSPACKET_H
#define PROCESSPACKET_H

#include <stdio.h>
#include <string.h>			// for memset
#include <iostream>			// for in/out
#include <arpa/inet.h>		// for ntohs, ntohl functions
#include <netinet/in.h>		// for struct sockaddr_in
#include <errno.h>			// for error message
#include <net/ethernet.h>	// for struct ethernet frame header
#include <netinet/ip.h>		// for struct ip packet header
#include <netinet/ip_icmp.h>	// for struct icmp header
#include <netinet/tcp.h>		// for struct tcp header
#include <netinet/udp.h>		// for struct udp header
#include <unistd.h>

using namespace std;



struct arpPacket{
	u_int16_t arp_hardType;
	u_int16_t arp_protType;
	u_int8_t arp_hardSize;
	u_int8_t arp_protSize;
	u_int16_t arp_op;
	u_int8_t senderEtherAddr[6];
	u_int8_t senderIPAddr[4];
	u_int8_t targetEtherAddr[6];
	u_int8_t targetIPAddr[4];
};

class ProcessPacket {
	private:
		void printEtherHeader(struct ether_header *ethhdr, const char *typeName);
		void printARPPacket(unsigned char *buf);
		void printIPHeader(unsigned char *buf);
		void printICMPPacket(unsigned char *buf);
		void printIGMPPacket(unsigned char *buf);
		void printTCPSegment(unsigned char *buf);
		void printUDPSegment(unsigned char *buf);
		void printData(unsigned char *data, int dataSize);
		char *macAddrToString(u_int8_t *mac);
		FILE *log;
		unsigned long frameNum;
		int dataSize;

	public:
		ProcessPacket(const char * fileName);
		void parsingFrame(unsigned char *buf, int dataSize);
};

#endif