#include <stdio.h>
#include <linux/filter.h>

// using namespace std;

int main(){
    struct sock_filter code[2];
    for(int i = 0; i < 2; i++)
         printf("Code: %.8X | Jump true: %u | Jump false: %u | K: %u\n", code[i].code, code[i].jt, code[i].jf, code[i].k);
    printf("\n");
    code[0].code = 1;
    code[0].jt = 2;
    code[0].jf = 3;
    code[0].k = 4;   
      for(int i = 0; i < 2; i++)
         printf("Code: %.8X | Jump true: %u | Jump false: %u | K: %u\n", code[i].code, code[i].jt, code[i].jf, code[i].k);
 
}