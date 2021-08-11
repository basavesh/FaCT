#include <stdio.h>
#include <stdint.h>

#include "lfence.h"

// register int ms_flag asm ("rbx");
//asm("mov 0, r9");
volatile uint64_t ms_flag = 0;
const char *base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz0123456789+/";

// uint64_t secdec(uint64_t input) {
//   asm("lfence":::"memory");
//   return input;
// }
// void ms_flag_true (int cond) {
//   ms_flag = cond ? ms_flag : 1;
// }

// void ms_flag_false (int cond) {
//   ms_flag = cond ? 1 : ms_flag;
// }

int main(void) {
  uint64_t key = 0x1d381f22be58ac3a;
  uint64_t msg[32] = {0x09a9d3591c6adb40,0,};



  uint64_t result;
  result = encrypt(msg, key);


  for(int i=0;i<10;i++) {
    printf("%c",base64[result & 0x3f]);
    result >>= 6;
  }
  printf("\n");
  return 0;
}
