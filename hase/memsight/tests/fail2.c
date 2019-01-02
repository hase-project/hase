#include <assert.h>

int a[2048] = { 0 };

void foobar(char * p) {
	*p = 7;
	if (p < 1000)
		assert(0);
}

void main() {
	char a;
	foobar(&a);
}
