#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#define XXX __asm__("nop");

/* 
 * musl-gcc -g -fno-plt -static control_flow.c -o control_flow
 * hase record ./control_flow a b c d e
 */

int main(int argc, char** argv) {
    XXX;
    volatile int a = argc;
    XXX;
    XXX;
    XXX;
    if(a>0xff) {
        XXX;
    }
    XXX;
    XXX;
    XXX;
    while(a<10) {
        XXX;
        a++;
        XXX;
    }
    XXX;
    XXX;
    XXX;
    for (a = 0; a < 10; a++) {
        XXX;
    }
    XXX;
    XXX;
    XXX;
    kill(getpid(), SIGABRT);
    return 0;
}

