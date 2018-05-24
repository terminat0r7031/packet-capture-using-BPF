#ifndef EXTENDSTRUCTURE_H
#define EXTENDSTRUCTURE_H
#include <stdint.h>
struct my_sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
    uint8_t reverse;
};

#ifndef MY_BPF_STMT
#define MY_BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k , 0}
#endif
#ifndef MY_BPF_JUMP
#define MY_BPF_JUMP(code, k, jt, jf, reverse) { (unsigned short)(code), jt, jf, k , reverse}
#endif
 

#endif