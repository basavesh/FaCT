#ifndef __AESIMPL_FACT_H
#define __AESIMPL_FACT_H

struct AES_KEY;
// struct AES_KEY {
//   /*secret*/ uint64_t rd_key;
//   /*public*/ int32_t rounds;
// };


void unrolled_fact(
  const /*secret*/ uint64_t __v1_plaintext[2],
  /*secret*/ uint64_t __v2_ciphertext[2],
  struct AES_KEY * __v3_key);

void looped_fact(
  const /*secret*/ uint64_t __v7_plaintext[2],
  /*public*/ uint64_t __v8_ciphertext[2],
  struct AES_KEY * __v9_key);







#endif /* __AESIMPL_FACT_H */