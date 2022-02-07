.PHONY: clean

aes: main.c aes_core.c aes.h aesimpl.c
	clang-11 -c -o aesimpl.o -O3 -maes -mspeculative-load-hardening aesimpl.c
	clang-11 -O3 main.c aes_core.c openssl_aesni.o aesimpl.o -o aes

clean:
	rm aesimpl.o aes