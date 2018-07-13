#include <stdio.h>
#include <stdlib.h>
#include <signal.h>


int main(int argc, char** argv) {
    char c;
    // test if symbol: getchar_1, ..., getchar_2 can be solved
    // or atof_symbol
    char num[20];
    size_t actual_read;
    char buf[20];
    actual_read = fread(buf, sizeof(buf), 1, stdin);
    double bvalue = atof(buf);
    printf("%f\n", bvalue);    
    int i = 0;
    while ((c = getchar()) != EOF) {
        num[i] = c;
        ++i;
    }
    num[i] = '\0';
    double value = atof(num);
    printf("%f\n", value);
    raise(SIGQUIT);
}
