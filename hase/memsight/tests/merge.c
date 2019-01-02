int foobar(int n) {
	int i;
	int sum = 0;
	for (i = 0; i < n; i++)
		sum = i;
	return sum;
}

int main() {
	int res = foobar(100);
	return 0;
}
