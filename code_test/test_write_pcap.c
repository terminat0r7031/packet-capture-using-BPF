#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <math.h>
#include <sys/time.h>
//#define Mask 0x0000FFFF
//#define FOUR 0x0000FF00
//#define FIVE 0x000F0000

#define FTWO 0x0000FF00
#define FONE 0x000000FF
#define FTH 0x000F0000

int rawSocket();
int setPromisc(char *,int *);

//int rval;                 //the number of receiving bytes,we need a local varvible

int main(int argc,char **argv)
{
    if(argc!=2)
    {
        perror("please echo like this:   ./mypack eth0\n");
        exit(1);
    }
 
    int sock;
    struct sockaddr_ll rcvaddr;
    char buf[6666];
    struct ifreq ifr;
    int len;

    sock=rawSocket();
    setPromisc(argv[1],&sock);
    len=sizeof(struct sockaddr);
    memset(buf,0,sizeof(buf));

	FILE *fi;
	fi=fopen("a.cap","ab+");
	if(fi == NULL)
	{
		printf("open a.cap failed!!\n");
	}

	//char head[] = "0xD4C3B2A1020004000000000000000000FFFF000001000000";
	//fprintf(fi,"D4C3B2A1020004000000000000000000FFFF000001000000");   //this is ascii,so wrong!!!

	/*******pcap header*******/
	struct pcap_file_header *fh;
	struct pcap_file_header p_f_h;
	p_f_h.magic = 0xA1B2C3D4;
	p_f_h.version_major = 0x0002;
	p_f_h.version_minor = 0x0004;
	p_f_h.thiszone = 0x00000000;
	p_f_h.sigfigs = 0x00000000;
	p_f_h.snaplen = 0x0000FFFF;
	p_f_h.linktype = 0X00000001;
	fh = &p_f_h;
	fwrite(fh,sizeof(p_f_h),1,fi);
	fclose(fi);

    while(1)
    {
	    int rval;      //the unit is byte!!!  so multiple 256
        rval=recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr*)&rcvaddr,&len);
        if(rval>0)
        {
//          printf("Get %d bytes\n",rval);
			FILE *f;
			f=fopen("a.cap","ab+");
			if(f==NULL)
			{
				printf("open /tmp/a.cap failed!!!\n");
			}

			struct timeval tv;
			gettimeofday(&tv,NULL);
			fwrite(&(tv.tv_sec),4,1,f);
			fwrite(&(tv.tv_usec),4,1,f);


		    // int b,c,d;
			// int *bp;	
			// b = rval*256;           //cause rval is the bytes of recvfrom()
			// /****switch the position*****/
            // printf("b before: %d\n", b);
			// if(b<0x00010000)
			// {
			// 	c = (b&FTWO)>>8;
			// 	d = (b&FONE)<<8;
			// 	b = c|d;
            //     printf("b after1: %d\n", b);
			// }
			// else
			// {
			// 	c = (b&FTWO)>>8;
			// 	d = (b&FTH)>>8;
            //     printf("b after2: %d\n", b);
			// 	b = c|d;
			// }

			// bp = &b;
            int bp = rval;
			fwrite(&bp,4,1,f);
			fwrite(&bp,4,1,f);

			fwrite(buf,rval,1,f);
			fclose(f);
        }

		else
	   		printf("recvfrom failed!!!\n");	
   	 }
    return 0;
}


int rawSocket()//
{
    int sock;
    //sock=socket(PF_INET,SOCK_RAW,IPPROTO_TCP);//frome IP
    sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));//frome Ethernet
    if(sock<0)
    {
        printf("create raw socket failed:%s\n",strerror(errno));
        exit(1);
    }
    
    printf("raw socket :%d created successful!\n",sock);
    return sock;
}


int setPromisc(char *enterface,int *sock)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, enterface);
    ifr.ifr_flags=IFF_UP|IFF_PROMISC|IFF_BROADCAST|IFF_RUNNING;
	//ifr.ifr_flags |= IFF_PROMISC;      // this is wrong code
    if(ioctl(*sock,SIOCSIFFLAGS,&ifr)==-1)
    {
        perror("set 'eth' to promisc model failed\n"); //cant write  '%s',enterface  why?
        exit(1);
    }
    printf("set '%s' to promisc successed!\n",enterface);
    return 1;
}
