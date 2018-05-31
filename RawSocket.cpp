#include "RawSocket.h"
RawSocket::RawSocket(){}
int RawSocket::showIf(){
	struct ifaddrs *ifaddr, *ifa;
	char *ifList;
	if(getifaddrs(&ifaddr) == -1){	// get link list of structures describing the network interfaces of the local system
		cerr<<"Error occurred, couldn't get interface list: "<<strerror(errno);
		exit(-1);
	}
	int i = 1;
	cout<<"Interface list: "<<endl;
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
		if(ifa->ifa_addr->sa_family == AF_INET){
			cout<<i++<<". "<<ifa->ifa_name<<endl;
		}
	}
	return 0;
}

int RawSocket::create(char *ifName){
	
	if(ifName == NULL){
		cerr<<"Error occurred, interface's name is empty!"<<endl;
		exit(-1);
	}

	// creating a raw socket
	rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (rawSock == -1){
		cerr<<"Error occurred, couldn't create raw socket: "<<strerror(errno)<<endl;
		exit(-1);
	}

	// // change the socket into non-blocking socket
	// fcntl(rawSock, F_SETFL, O_NONBLOCK);

	// find interface index
	unsigned int ifIndex;
	if((ifIndex = if_nametoindex(ifName)) == 0){
		cerr<<"Error occurred, interface \""<<ifName<<"\" is invalid: "<<strerror(errno)<<endl;
		exit(-1);
	}

	// binding this raw socket to ifName interface
	struct sockaddr_ll sll;
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifIndex ; 
	
	bind(rawSock, (struct sockaddr *) &sll, socklen_t(sizeof(sll)));
	return rawSock;
}

void RawSocket::applyFilter(struct sock_fprog bpf){
	if(setsockopt(rawSock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) == -1){
		cout << "Couldn't apply filter" << endl;
		exit(-1);		
	}
}