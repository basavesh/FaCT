The following files are copied directly from https://github.com/openssl/openssl
They have minor changes (commenting some includes and adding typedefs) to allow compilation without the remainder of openssl.
    aes.h
    aes_core.c

The following files are objects compiled using code from https://github.com/openssl/openssl
-- TODO: Get source into the repo and build from source instead.
    openssl_aesni.o
