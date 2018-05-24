#ifndef RAWSOCKET_H
#define RAWSOCKET_H

#include <iostream>
#include <stdlib.h>				
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>			
#include <sys/ioctl.h>
#include <net/if.h>				
#include <ifaddrs.h>			// for searching interfaces name
#include <errno.h>				// for error message
#include <linux/filter.h>		// for applying BPF packet filter
#include <queue>
#include <string.h>				// for strerror
#include <linux/if_ether.h>		// for ETH_P_ALL macro
#include <linux/if_packet.h>	// for struct sockaddr_ll
#include <fcntl.h>				// for nonblocking socket	

using namespace std;

class RawSocket {
	private:
		char * ifName;
		int rawSock;
		
	public:
		RawSocket();
		int create(char *ifName);
		int showIf();
		void applyFilter(struct sock_fprog bpf);
};
#endif