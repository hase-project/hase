
CC 		= gcc
CCFLAGS = -g # -static
SRCS	= ./src
BINS	= ./bin
HASEBIN	= ../bin/hase
TARGETS = control_flow loopy long_trace null_deref core_constraint heap_location


$(TARGETS): 
	$(CC) $(CCFLAGS) $(SRCS)/$@/$@.c -o $(BINS)/$@

%_record:
	sudo $(HASEBIN) record --limit=1 $(BINS)/$* 10 0