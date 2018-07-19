#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

struct Test {
    int a;
    void* p;
};

int main(int argc, char** argv) {
    // if p is like variable('malloc_xxxx'), repair it's address?
    struct Test* p = (struct Test*)malloc(sizeof(struct Test));
    p->a = 20;
    p->p = malloc(sizeof(struct Test));
    raise(SIGQUIT);
}
