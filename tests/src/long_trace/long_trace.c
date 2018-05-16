#include <stdio.h>
#include <stdlib.h>


int some_function(int argc, int crash) {
    for (int i = 0; i < argc; ++i) {
       printf("%d\n", i);
    }
    printf("%f\n", 1/crash);
}

/* 
 * Test partial trace and scalability
 * musl-gcc -g -fno-plt -static long_trace.c -o long_trace
 * hase record ./long_trace 1000000 0
 */

int main(int argc, char** argv) {
  if (argc > 2) {
    some_function(atoi(argv[1]), atoi(argv[2]));
  }
}
