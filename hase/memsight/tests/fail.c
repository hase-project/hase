#include <assert.h>

int a[2048] = { 0 };

void foobar(unsigned i, unsigned j) {
	if (j >= 2048) return;
	a[i] = 5;
	assert(a[j] != 5);
}

void main() {
	foobar(0, 1);
}
