#include <stdio.h>
#include <stdint.h>

#include "simple.h"

const char *base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz0123456789+/";

uint64_t secdec(uint64_t input) {
  asm("lfence":::"memory");
  return input;
}

int main(void) {
  uint64_t key = 0x1d381f22be58ac3a;
  uint64_t msg = 0x09a9d3591c6adb40;

  msg = encrypt(msg, key);
  // declassify(msg); 

  for(int i=0;i<10;i++) {
    printf("%c",base64[msg & 0x3f]);
    msg >>= 6;
  }
  printf("\n");
  return 0;
}
