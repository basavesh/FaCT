.PHONY: clean

aes: main.c aes_core.c aes.h aesimpl.fact
	../../../factc -generate-header -llvm-out  -opt O3 -addl "-maes -mspeculative-load-hardening" aesimpl.fact
	clang-11 main.c aes_core.c openssl_aesni.o aesimpl.o -o aes
	objdump -D aes > aes.s

clean:
	rm aesimpl.o aesimpl.h aesimpl.ll aesimpl.bc aesimpl.s aes aes.s