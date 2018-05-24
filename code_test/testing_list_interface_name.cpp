#include <iostream>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
using namespace std;
int main(){
	string addr;
	addr = "con meo";
	printf("%s\n", addr.c_str());
	struct ifaddrs *ifa, *ifaddr;
	if (getifaddrs(&ifaddr) == -1){
		cout<<"Error occurred!";
		exit(-1);
	}
	int i = 0;
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
		cout<<"Family code: "<<ifa->ifa_addr->sa_family<<endl;
		cout<<ifa->ifa_name<<endl;
		struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
		cout<<"Address: "<<inet_ntoa(sin->sin_addr)<<endl;
	}
}