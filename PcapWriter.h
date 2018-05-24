#ifndef PCAPWRITER_H
#define PCAPWRITER_H
#include <stdio.h>          // for fwrite()
#include <pcap/pcap.h>      // for structure pcap_file_header
#include <sys/time.h>       // for struct timeval, gettimeofday()
#include <string>
#include <iostream>

using namespace std;

class PcapWriter{
    private:
        string fileName;
    public:
        PcapWriter(const char *fileName){
            this->fileName = string(fileName);
            FILE *fp;
            fp = fopen(this->fileName.c_str(), "wb");
            if(fp == NULL){
                cerr<<"Error occurred, couldn't open \""<<fileName<<"\""<<endl;
                exit(-1);
            }
            struct pcap_file_header pfh;
            pfh.magic = 0xa1b2c3d4;
            pfh.version_major = 0x0002;             // version 2.4
            pfh.version_minor = 0x0004;
            pfh.thiszone = 0x00000000;
            pfh.sigfigs = 0x00000000;
            pfh.snaplen = 0x0000FFFF;               // 65535 bytes
            pfh.linktype = 0x00000001;              // ethernet
            fwrite(&pfh, sizeof(pfh), 1, fp);
            fclose(fp);
        }
        void writeToFile(unsigned char* buf, int dataSize){
            FILE *fp;
            fp = fopen(fileName.c_str(), "ab+");
            struct timeval tv;
            gettimeofday(&tv, NULL);
            fwrite(&(tv.tv_sec), 4, 1, fp);         // write timestamp in seconds
            fwrite(&(tv.tv_usec), 4, 1, fp);        // write timestamp in micro-seconds
            fwrite(&dataSize, 4, 1, fp);            // write number of octets of packet saved in file
            fwrite(&dataSize, 4, 1, fp);            // write actual length of packet
            fwrite(buf, dataSize, 1, fp);           // write packet's data
            fclose(fp);
        }   
};

#endif
