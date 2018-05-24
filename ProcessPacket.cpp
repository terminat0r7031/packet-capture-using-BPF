#include "ProcessPacket.h"

ProcessPacket::ProcessPacket(const char *fileName){
	log = fopen(fileName, "w");
	if(log == NULL){
		cout<<"Error occurred, coudn't open \""<<fileName<<"\" file"<<endl;
		exit(-1);
	}
}

void ProcessPacket::parsingFrame(unsigned char *buf, int dataSize){ // parsing only IPv4 and ARP/RARP
	this->dataSize = dataSize;
	frameNum++;
	struct ether_header *ethhdr = (struct ether_header *)buf;
	switch (ntohs(ethhdr->ether_type)){
		case 0x0800: // IPv4
			printEtherHeader(ethhdr, "IPv4");
			printIPHeader(buf + sizeof(struct ether_header));	
			break;
		case 0x0806: // ARP for IPv4 only
			printEtherHeader(ethhdr, "ARP");
			printARPPacket(buf + sizeof(struct ether_header));
			break;
		case 0x8035: // RARP for IPv4 only
			printEtherHeader(ethhdr, "RARP");
			printARPPacket(buf + sizeof(struct ether_header));
			break;
	}
}

void ProcessPacket::printEtherHeader(struct ether_header *ethhdr, const char *typeName){
	fprintf(log, "Frame number: %ld\n", frameNum);
	fprintf(log , "Frame size: %d\n", dataSize);
	fprintf(log, "Ethernet header\n");
	fprintf(log, "		|- Destination address: %s\n", macAddrToString(ethhdr->ether_dhost));
	fprintf(log, "		|- Source address: %s\n", macAddrToString(ethhdr->ether_shost));
	fprintf(log, "		|- Type: %.4X (%s)\n", ntohs(ethhdr->ether_type), typeName);
}

void ProcessPacket::printARPPacket(unsigned char *buf){
	struct arpPacket *arpPkt = (struct arpPacket *)buf;
	if(ntohs(arpPkt->arp_hardType) == 1){		// Ethernet and IPv4 only
		struct sockaddr_in sender, target;
		memset(&sender, 0, sizeof(struct sockaddr_in));
		sender.sin_addr.s_addr = *(u_int32_t *)arpPkt->senderIPAddr;

		memset(&target, 0, sizeof(struct sockaddr_in));
		target.sin_addr.s_addr = *(u_int32_t *)arpPkt->targetIPAddr;

		fprintf(log, "\n");
		fprintf(log, "Address Resolution Protocol\n");
		fprintf(log, "		|- Hardware type: Ethernet (%u)\n", ntohs(arpPkt->arp_hardType));
		fprintf(log, "		|- Protocol type: IPv4 (%u)\n", ntohs(arpPkt->arp_protType));
		fprintf(log, "		|- Hardware size: %u\n", arpPkt->arp_hardSize);
		fprintf(log, "		|- Protocol size: %u\n", arpPkt->arp_protSize);
		switch (ntohs(arpPkt->arp_op)){
			case 1:
				fprintf(log, "		|- Opcode: ARP Request (%u)\n", ntohs(arpPkt->arp_op));
				break;
			case 2:
				fprintf(log, "		|- Opcode: ARP Reply (%u)\n", ntohs(arpPkt->arp_op));
				break;
			case 3:
				fprintf(log, "		|- Opcode: RARP Request (%u)\n", ntohs(arpPkt->arp_op));
				break;
			case 4:
				fprintf(log, "		|- Opcode: RARP Reply (%u)\n", ntohs(arpPkt->arp_op));
				break;
		}
		fprintf(log, "		|- Sender MAC address: %s\n", macAddrToString(arpPkt->senderEtherAddr));
		fprintf(log, "		|- Sender IP address: %s\n", inet_ntoa(sender.sin_addr));
		fprintf(log, "		|- Target MAC address: %s\n", macAddrToString(arpPkt->targetEtherAddr));
		fprintf(log, "		|- Target IP address: %s\n", inet_ntoa(target.sin_addr));
		fprintf(log, "\n*****************************************************************************\n");
		fflush(log);
	}
}

void ProcessPacket::printIPHeader(unsigned 	char *buf){
	struct iphdr *ipHdr = (struct iphdr *)buf;
	struct sockaddr_in source, dest;
	memset(&source, 0, sizeof(struct sockaddr_in));
	memset(&dest, 0, sizeof(struct sockaddr_in));
	
	source.sin_addr.s_addr = ipHdr->saddr;
	dest.sin_addr.s_addr = ipHdr->daddr;

	fprintf(log, "\n");
	fprintf(log, "Internet Protocol Version 4\n");
	fprintf(log, "		|- Version: %u\n", (unsigned int)ipHdr->version);
	fprintf(log, "		|- Header length: %u (bytes)\n", (unsigned int)ipHdr->ihl * 4);
	fprintf(log, "		|- Type of service: %u\n", (unsigned int)ipHdr->tos);
	fprintf(log, "		|- Total length: %u\n", ntohs(ipHdr->tot_len));
	fprintf(log, "		|- Identification: %u\n", ntohs(ipHdr->id));
	fprintf(log, "		|- Flags:\n");
	u_int16_t frag = ntohs(ipHdr->frag_off);
	fprintf(log, "			+ Reserved bit: %u\n", (frag&0x8000)>>15);
	fprintf(log, "			+ Don't fragment: %u\n", (frag&0x4000)>>14);
	fprintf(log, "			+ More fragments: %u\n", (frag&0x2000)>>13);
	fprintf(log, "		|- Fragment offset: %u\n", frag&0x00FF);
	fprintf(log, "		|- Time to live: %u\n", (unsigned int)ipHdr->ttl);
	switch (ipHdr->protocol){
		case 1: // ICMP
			fprintf(log, "		|- Protocol: ICMP (%u)\n", ipHdr->protocol);
			break;
		case 2: // IGMP
			fprintf(log, "		|- Protocol: IGMP (%u)\n", ipHdr->protocol);
			break;
		case 6: // TCP
			fprintf(log, "		|- Protocol: TCP (%u)\n", ipHdr->protocol);
			break;
		case 17: // UDP
			fprintf(log, "		|- Protocol: UDP (%u)\n", ipHdr->protocol);
			break;
	}
	fprintf(log, "		|- Header checksum: 0x%.4X\n", ntohs(ipHdr->check));
	fprintf(log, "		|- Source: %s\n", inet_ntoa(source.sin_addr));
	fprintf(log, "		|- Destination: %s\n", inet_ntoa(dest.sin_addr));

	switch (ipHdr->protocol){
		case 1: // ICMP
			printICMPPacket(buf + sizeof(struct iphdr));
			break;
		case 2: // IGMP
			// printIGMPPacket(buf + sizeof(struct iphdr));
			break;
		case 6: // TCP
			printTCPSegment(buf + sizeof(struct iphdr));
			break;
		case 17: // UDP
			printUDPSegment(buf + sizeof(struct iphdr));
			break;
	}
}

void ProcessPacket::printICMPPacket(unsigned char *buf){
	struct icmphdr *icmpHdr = (struct icmphdr *)buf;
	string type, code;
	switch (icmpHdr->type){
		case 0:
			type = "echo reply";
			break;
		case 3:
			type = "destination unreachable";
			switch (icmpHdr->code){
				case 0:
					code = "network unreachable";
					break;
				case 1:
					code = "host unreachable";
					break;
				case 2:
					code = "protocol unreachable";
					break;
				case 3:
					code = "port unreachable";
					break;
				case 4:
					code = "fragmentation needed but don't-fragment bit set";
					break;
				case 5:
					code = "source route failed";
					break;
				case 6:
					code = "destination network unknown";
					break;
				case 7:
					code = "destination host unknown";
					break;
				case 8:
					code = "source host ioslated (obsolete)";
					break;
				case 9:
					code = "destination network administratively prohibited";
					break;
				case 10:
					code = "destination host administratively prohibited";
					break;
				case 11:
					code = "network unreachable for TOS";
					break;
				case 12:
					code = "host unreachable for TOS";
					break;
				case 13:
					code = "communication administratively prohibited by filtering";
					break;
				case 14:
					code = "host precedence violation";
					break;
				case 15:
					code = "precedence cutoff in effect";
					break;	
			}
			break;
		case 4:
			type = "source quench";
			break;
		case 5:
			type = "redirect";
			switch (icmpHdr->code){
				case 0:
					code = "redirect for network";
					break;
				case 1:
					code = "redirect for host";
					break;
				case 2:
					code = "redirect for type-of-service and network";
					break;
				case 3:
					code = "redirect for type-of-service and host";
					break;
			}
			break;
		case 8:
			type = "echo request";
			break;
		case 9:
			type = "router advertisement";
			break;
		case 10:
			type = "router solicitation";
			break;
		case 11:
			type = "time exceeded";
			switch (icmpHdr->code){
				case 0:
					code = "time-to-live equals 0 during transit";
					break;
				case 1:
					code = "time-to-live equals 0 during reassembly";
					break;
			}
			break;
		case 12:
			type = "parameter problem";
			switch (icmpHdr->code){
				case 0:
					code = "IP header bad (catchall error)";
					break;
				case 1:
					code = "required option missing";
					break;
			}
			break;
		case 13:
			type = "timestamp request";
			break;
		case 14:
			type = "timestamp reply";
			break;
		case 15:
			type = "information request";
			break;
		case 16:
			type = "information reply";
			break;
		case 17:
			type = "address mask request";
			break;
		case 18:
			type = "address mask reply";
			break;
	}
	fprintf(log, "\n");
	fprintf(log, "Internet Control Message Protocol\n");
	fprintf(log, "		|- Type: %s (%u)\n", type.c_str(), icmpHdr->type);
	fprintf(log, "		|- Code: %s (%u)\n", code.c_str(), icmpHdr->code);
	fprintf(log, "		|- Checksum: %u\n", ntohs(icmpHdr->checksum));
	fprintf(log, "\n*****************************************************************************\n");
	fflush(log);
}

void ProcessPacket::printTCPSegment(unsigned char *buf){
	struct tcphdr *tcpHdr = (struct tcphdr *)buf;
	fprintf(log, "\n");
	fprintf(log, "Transmission Control Protocol\n");
	fprintf(log, "		|- Source port number: %u\n", ntohs(tcpHdr->th_sport));
	fprintf(log, "		|- Destination port number: %u\n", ntohs(tcpHdr->th_dport));
	fprintf(log, " 		|- Sequence number: %u\n", ntohs(tcpHdr->th_seq));
	fprintf(log, " 		|- Acknowledgment number: %d\n", ntohs(tcpHdr->th_ack));
	fprintf(log, "		|- Header length: %u (bytes)\n", tcpHdr->th_off * 4);
	fprintf(log, "		|- Flags:\n");
	fprintf(log, "			+ URG: %u\n", ((tcpHdr->th_flags)&0x20)>>5);
	fprintf(log, " 			+ ACK: %u\n", ((tcpHdr->th_flags)&0x10)>>4);
	fprintf(log, "			+ PSH: %u\n", ((tcpHdr->th_flags)&0x08)>>3);
	fprintf(log, "			+ RST: %u\n", ((tcpHdr->th_flags)&0x04)>>2);
	fprintf(log, " 		 	+ SYN: %u\n", ((tcpHdr->th_flags)&0x02)>>1);
	fprintf(log, "			+ FIN: %u\n", ((tcpHdr->th_flags)&0x01));
	fprintf(log, "		|- Window size: %u\n", ntohs(tcpHdr->th_win));
	fprintf(log, "		|- TCP checksum: 0x%.4X\n", ntohs(tcpHdr->th_sum));
	fprintf(log, " 		|- Urgent pointer: %u\n", ntohs(tcpHdr->th_urp));
	// didn't show options field
	// data field start from buf + tcp_header_length
	fprintf(log, "\nPayload\n");
	printData(buf + tcpHdr->th_off * 4, dataSize - sizeof(struct ether_header) - sizeof(struct iphdr) - tcpHdr->th_off * 4);
}

void ProcessPacket::printUDPSegment(unsigned char *buf){
	struct udphdr *udpHdr = (struct udphdr*)buf;
	fprintf(log, "\n");
	fprintf(log, "User Datagram Protocol\n");
	fprintf(log, "		|- Source port number: %u\n", ntohs(udpHdr->uh_sport));
	fprintf(log, " 		|- Destination port number: %u\n", ntohs(udpHdr->uh_dport));
	fprintf(log, "		|- UDP length: %u (bytes)\n", ntohs(udpHdr->uh_ulen));
	fprintf(log, "		|- UDP checksum: 0x%.4X\n", ntohs(udpHdr->uh_sum));
	fprintf(log, "\nPayload\n");
	printData(buf + sizeof(struct udphdr), dataSize - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct udphdr));
}

char *ProcessPacket::macAddrToString(u_int8_t *mac){
	static char macString[18];
	char hexCode[17] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', ':'};
	int macStringIndex = 0;
	for(int i = 0; i < 6; i++){
		if (mac[i] < 0x10){
			macString[macStringIndex++] = '0';
			char digit = hexCode[(mac[i]%16)];
			macString[macStringIndex++] = digit;
		}
		else {
			int temp = mac[i];
			char digitLatter = hexCode[(temp%16)];
			temp /= 16;
			char digitFormer = hexCode[(temp%16)];
			macString[macStringIndex++] = digitFormer;
			macString[macStringIndex++] = digitLatter;
		}
		if( i != 5){
			macString[macStringIndex++] = hexCode[16];
		}
	}
	macString[17] = '\0';
	return macString;
}	

void ProcessPacket::printData(unsigned char *data, int dataSize){
	for(int i = 0; i < dataSize; i++){
		if( i != 0 && i%16 == 0){		// printing 16 bytes in hex presentation then print char presentation
			fprintf(log, "         ");  // adding space between hex and char
			for(int j = i - 16; j < i; j++){
				if (data[j] >= 32 && data[j] <= 126){	// only print ascii printable
					fprintf(log, "%c", (unsigned char) data[j]);
				}
				else
					fprintf(log, ".");	// otherwise print dot sign "."
			}
			fprintf(log, "\n");
		}
		if (i % 16 == 0)
			fprintf(log, "       ");	// adding space before printing
		fprintf(log, "%.2X ", (unsigned int)data[i]);
		if (i == dataSize - 1){		// for the last character
			for(int j = 0; j < 16 - (dataSize%16); j++)
				fprintf(log, "   ");
			fprintf(log, "         ");
			for(int j = i - dataSize%16; j < i; j++){
				if (data[j] >= 32 && data[j] <= 126){	// only print ascii printable
					fprintf(log, "%c", (unsigned char) data[j]);
				}
				else
					fprintf(log, ".");	// otherwise print dot sign "."
			}
			fprintf(log, "\n");
		}
	}
	fprintf(log, "\n*****************************************************************************\n");
	fflush(log);
}