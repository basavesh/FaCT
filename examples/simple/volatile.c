#include <stdio.h>

int test() {
    volatile int y;
    return 5;
}

int main() {
    volatile int x = 0x1234;
    printf("Hello world %d\n", test());
    return 0;
}