CC = musl-gcc

all: exec-wrapper

exec-wrapper: exec-wrapper.c
	$(CC) -static -o exec-wrapper exec-wrapper.c

clean:
	rm -rf exec-wrapper
