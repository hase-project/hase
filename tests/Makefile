
CC 		= gcc
CCFLAGS = -g # -static
SRCS	= ./src
BINS	= ./bin
HASEBIN	= ../bin/hase
C_TARGETS = control_flow long_trace null_deref core_constraint heap_location


all: $(C_TARGETS) loopy

loopy: src/loopy/loopy.S
	$(CC) -nostdlib $(SRCS)/loopy/loopy.S -o $(BINS)/$@

$(C_TARGETS): 
	$(CC) $(CCFLAGS) $(SRCS)/$@/$@.c -o $(BINS)/$@

%_record:
	sudo $(HASEBIN) record --limit=1 $(BINS)/$* 10 0
