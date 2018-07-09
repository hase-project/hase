#include <stdio.h>
#include <stdlib.h>


struct Test {
    int a;
    void* p;
};


int some_function(int argc, int crash) {
    for (int i = 0; i < argc; ++i) {
       printf("%d\n", i);
    }
    // avoid amd64g_dirtyhelper_storeF80
    struct Test* p = (struct Test*)malloc(sizeof(struct Test));
    p->a = 20;
    p->p = malloc(sizeof(struct Test));
    printf("%d\n", 1/crash);
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
