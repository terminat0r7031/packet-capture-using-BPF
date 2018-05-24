#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <iostream>
#include <getopt.h>
#include <sys/time.h>
#include <unistd.h>


#include "RawSocket.cpp"
#include "ProcessPacket.cpp"
#include "Parser.cpp"
#include "PcapWriter.h"

#define BUFSIZE 2048

using namespace std;

void printUsage()
{
	cout<<endl<<endl;
	cout<< "Please run this program with \"sudo\""<<endl;
	cout<< "Capturing IPv4 packet for specified interface" << endl;
	cout<< "Usage: sudo ./simpleCapture -i <interface's name> -o <output file> -t <type of output-file> [-l] [ -e expression ]" << endl;
	cout<< endl;
	cout<<"Options:"<<endl;
	cout<<"		-i			interface's name"<<endl;
	cout<<"		-o			output-file's name"<<endl;
	cout<<"		-t			type of output-file:"<<endl;
	cout<<"						-t 0 -> text file"<<endl;
	cout<<"						-t 1 -> cap file"<<endl;
	cout<<"		-l			list interfaces"<<endl;
	cout<<"		-e			expression"<<endl;
	cout<<endl;
	cout<<"Expression syntax:  field comparison-operator value [logical-operator]"<<endl;
	cout<<"    Fields: ver | hdrlen | tos | ttlen | ttl | proto | src | dst"<<endl;
	cout<<"    Comparison operators: \"==\" | \"!=\" | \">\" | \">=\" | \"<\" | \"<=\""<<endl;
	cout<<"    Logical operators: \"||\" | \"&&\""<<endl<<endl;
}

struct sock_filter bpfCode[50];
struct sock_fprog bpfProg = {
	.len = 0,
	.filter = bpfCode,
};

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printUsage();
		exit(-1);
	}
	RawSocket rawSock;
	Parser parser;


	int option, 
		iflag = 0,				// -i option flag 
		oflag = 0, 				// -o option flag
		tflag = 0,				// -t option flag
		eflag = 0; 				// -e option flag
	
	char *ip = NULL,					// pointer for -i option's argument
		 *op = NULL,					// pointer for -o option's argument
		 *tp = NULL, 					// pointer for -t option's argument
		 *ep = NULL;					// pointer for -e option's argument


	while ((option = getopt(argc, argv, "i:o:t:le:")) != -1)
	{
		switch (option)	{
			case 'i': {
				ip = optarg;
				iflag = 1;
				break;
			}
			case 'o': {
				op = optarg;
				oflag = 1;
				break;
			}
			case 't': {
				tp = optarg;
				tflag = 1;
				break;
			}
			case 'e': {
				ep = optarg;
				eflag = 1;
				break;
			}
			case 'l':{
				rawSock.showIf();
				exit(0);
			}
			default: {
				printUsage();
				exit(-1);
			}
		}
	}
	if(iflag == 0){
		cout<<"Synax error: missing -i option"<<endl;
		exit(-1);
	}
	if(oflag == 0){
		cout<<"Syntax error: missing -o option"<<endl;
		exit(-1);
	}
	if(tflag == 0){
		cout<<"Syntax error: missing -t option"<<endl;
		exit(-1);
	}

	// Create raw socket file description
	int rSock;
	rSock = rawSock.create(ip);

	// check if expression is exist
	if(eflag == 1){
		FILE *ef = fopen(ep, "r");
		if(ef == NULL) {
			cout<<"Error occurred, coudn't open \""<<ep<<"\" file"<<endl;
			exit(-1);
		}
		char *line;
		size_t n;
		getline(&line, &n, ef);
		parser.lexicalAnalysis(string(line));
		parser.genCode(bpfCode, &bpfProg);

		// check filter code is valid or not
		rawSock.applyFilter(bpfProg);
	}

	// Allocate memory for buf
	unsigned char *buf;								// buffer for store data
	buf = (unsigned char *)malloc(BUFSIZE);

	fd_set rfds;
	struct timeval tv;
	int retval;
	int dataSize;

	FD_ZERO(&rfds);
	FD_SET(rSock, &rfds);

	if(string(tp) == "0"){
		cout<<"Packet capture is starting..."<<endl;
		ProcessPacket psPkt(op);
			while(1){
			// Wait up to 20 seconds
			tv.tv_sec = 20;

			retval = select(rSock + 1, &rfds, NULL, NULL, &tv);
			// Don't rely on the value of tv now

			if(retval == -1){
				cerr<<"Error occurred, couldn't call select(): "<<strerror(errno)<<endl;
				exit(-1);
			}		
			else if(retval == 1){
				dataSize = recvfrom(rSock, buf, BUFSIZE, 0, NULL, NULL); // for receive packet from all source
				psPkt.parsingFrame(buf, dataSize);
			}
			else{
				cout<<"No data within 20 seconds"<<endl;
				close(rSock);
				exit(0);
			}
		}
	}
	else if(string(tp) == "1"){
		cout<<"Packet capture is starting..."<<endl;
		PcapWriter pcapWriter(op);
		while(1){
			// Wait up to 20 seconds
			tv.tv_sec = 20;

			retval = select(rSock + 1, &rfds, NULL, NULL, &tv);
			// Don't rely on the value of tv now

			if(retval == -1){
				cerr<<"Error occurred, couldn't call select(): "<<strerror(errno)<<endl;
				exit(-1);
			}		
			else if(retval == 1){
				dataSize = recvfrom(rSock, buf, BUFSIZE, MSG_DONTWAIT, NULL, NULL); // for receive packet from all source
				pcapWriter.writeToFile(buf, dataSize);
			}
			else{
				cout<<"No data within 20 seconds"<<endl;
				close(rSock);
				exit(0);
			}
		}
	}
}