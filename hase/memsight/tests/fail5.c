#include <assert.h>

char a[2] = { 0 };

void foobar(unsigned i, unsigned j) {
	if (i > 1 || j > 1) return;
	a[i] = 5;
	assert(a[j] != 5);
}

void main() {
	foobar(0, 1);
}
