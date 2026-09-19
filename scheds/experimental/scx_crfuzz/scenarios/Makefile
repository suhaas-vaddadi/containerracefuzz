# Built -static on purpose: a dynamically-linked binary's loader makes dozens
# of openat/readlinkat/fstatat calls before main(), every one of which is a
# checkpoint in the section 4.2 structural set. That is a real finding about
# instrumenting real targets, but it is noise in a scenario meant to isolate
# two syscalls.
CFLAGS ?= -O0 -g -Wall -Wextra -static

all: victim racer threaded_victim go_victim

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $<

racer: racer.c
	$(CC) $(CFLAGS) -o $@ $<

# -pthread: the sibling thread is the entire point of this fixture.
threaded_victim: threaded_victim.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

# CGO_ENABLED=0: a cgo binary drags in the dynamic loader, whose own
# path-touching syscalls before main() are all structural checkpoints. Static
# keeps the trace down to the two syscalls the scenario is about.
go_victim: go_victim.go
	CGO_ENABLED=0 go build -o $@ $<

clean:
	rm -f victim racer threaded_victim go_victim

.PHONY: all clean
