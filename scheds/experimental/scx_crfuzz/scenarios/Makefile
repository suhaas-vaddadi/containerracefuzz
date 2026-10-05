# Scenario fixtures and run targets.
#
# Three scenarios, one folder each, in increasing order of complexity:
#   01-single-thread   single victim + single attacker        (make run-01)
#   02-multi-thread    threaded victim + threaded attacker     (make run-02)
#   03-containerd-runc runc under containerd + two attackers   (make run-03)
# `fixtures/` holds binaries the Rust integration tests exec; they belong to no
# scenario but are built by `make all` so `cargo test` has them.
#
# Built -static on purpose: a dynamically-linked binary's loader makes dozens of
# openat/readlinkat/fstatat calls before main(), every one a checkpoint in the
# structural set -- noise in a scenario meant to isolate a few syscalls.
CFLAGS ?= -O0 -g -Wall -Wextra -static

S1 := 01-single-thread
S2 := 02-multi-thread
S3 := 03-containerd-runc
FIX := fixtures

all: build

# Everything the scenarios and the tests need built.
build: \
	$(S1)/victim $(S1)/racer \
	$(S2)/threaded_victim $(S2)/mt_attacker \
	$(S3)/mt_attacker \
	$(FIX)/go_victim $(FIX)/mt_hold

$(S1)/victim: $(S1)/victim.c
	$(CC) $(CFLAGS) -o $@ $<

$(S1)/racer: $(S1)/racer.c
	$(CC) $(CFLAGS) -o $@ $<

# -pthread: the sibling threads are the entire point of these fixtures.
$(S2)/threaded_victim: $(S2)/threaded_victim.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

$(S2)/mt_attacker: $(S2)/mt_attacker.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

# Scenario 3 runs the same attacker; built from scenario 2's source so there is
# one copy of it, placed where the runc wrapper (its own folder) looks.
$(S3)/mt_attacker: $(S2)/mt_attacker.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

# -pthread: thread-level (per-tid) hold fixture for tests/thread_hold.rs.
$(FIX)/mt_hold: $(FIX)/mt_hold.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

# CGO_ENABLED=0: a cgo binary drags in the dynamic loader, whose own
# path-touching syscalls before main() are all structural checkpoints.
$(FIX)/go_victim: $(FIX)/go_victim.go
	CGO_ENABLED=0 go build -o $@ $<

# Run targets: build the scenario's binaries, then run it. Each run.sh uses sudo
# (seccomp user-notify needs root); 02 and 03 also need scx_crfuzz_gated running.
run-01: $(S1)/victim $(S1)/racer
	$(S1)/run.sh

run-02: $(S2)/threaded_victim $(S2)/mt_attacker
	$(S2)/run.sh

run-03: $(S3)/mt_attacker
	$(S3)/run.sh

clean:
	rm -f $(S1)/victim $(S1)/racer \
	      $(S2)/threaded_victim $(S2)/mt_attacker \
	      $(S3)/mt_attacker \
	      $(FIX)/go_victim $(FIX)/mt_hold

.PHONY: all build run-01 run-02 run-03 clean
