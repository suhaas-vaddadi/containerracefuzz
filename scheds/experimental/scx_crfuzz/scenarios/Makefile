# Built -static on purpose: a dynamically-linked binary's loader makes dozens
# of openat/readlinkat/fstatat calls before main(), every one of which is a
# checkpoint in the section 4.2 structural set. That is a real finding about
# instrumenting real targets, but it is noise in a scenario meant to isolate
# two syscalls.
CFLAGS ?= -O0 -g -Wall -Wextra -static

all: victim racer

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $<

racer: racer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f victim racer

.PHONY: all clean
