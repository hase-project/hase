
CC 		= musl-gcc
CCFLAGS = -g -static # -fno-plt
SRCS	= ./src
BINS	= ./bin
HASEBIN	= ../bin/hase
TARGETS = control_flow loopy long_trace


$(TARGETS): 
	$(CC) $(CCFLAGS) $(SRCS)/$@/$@.c -o $(BINS)/$@

%_record:
	sudo $(HASEBIN) record --limit=1 $(BINS)/$* 10 0