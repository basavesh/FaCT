.PHONY: clean

aes: main.c aes_core.c aes.h aesimpl.c aesimpl_fact.fact
	../../factc -generate-header -llvm-out  -opt O3 -addl "-maes" aesimpl_fact.fact
	${CC} -c -o aesimpl.o -O3 -maes aesimpl.c
	${CC} -O3 main.c aes_core.c openssl_aesni.o aesimpl.o aesimpl_fact.o -o aes
	objdump -D aes > aes.s

clean:
	rm aesimpl.o aesimpl_fact.o aes aes.s aesimpl_fact.h aesimpl_fact.ll aesimpl_fact.bc aesimpl_fact.s