// SPDX-License-Identifier: GPL-2.0
//
// The smallest useful multithreaded role for exercising *thread-level* holds.
//
// One thread group with two kinds of thread:
//
//   - worker threads, which only write one byte per millisecond to a per-thread
//     progress file. `write` to an already-open fd is not a structural
//     checkpoint, so a worker never parks on its own: if a worker stops making
//     progress it is because the *gate* held it, not seccomp. This is what makes
//     the test measure the gate rather than the seccomp backend underneath it.
//
//   - the main thread, which loops on `fstatat`. `newfstatat` is the one
//     checkpoint the test attaches, so the main thread parks repeatedly and
//     gives the test a notification (a tid) to hold.
//
// The point of the split is the design discussion's "actor granularity": a role
// is a thread group, but scheduling its *threads* one at a time needs a hold
// keyed on the thread, not the group. Gating a worker's tid must freeze exactly
// that worker while its siblings keep running.
//
// Built -static for the same reason victim.c is: the dynamic loader's own
// path-touching startup calls would each be a checkpoint.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *target;

static void *worker(void *arg) {
    long i = (long)arg;
    char pf[512];
    snprintf(pf, sizeof pf, "%s.%ld", getenv("CRFUZZ_PROGRESS"), i);
    int pfd = open(pf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pfd < 0) {
        (void)!write(1, "VERDICT:progress-open-failed\n", 29);
        return NULL;
    }
    struct timespec nap = {.tv_sec = 0, .tv_nsec = 1000000}; // 1ms
    for (;;) {
        (void)!write(pfd, ".", 1);
        nanosleep(&nap, NULL);
    }
    return NULL;
}

int main(int argc, char **argv) {
    // <target> <progress-prefix> <workers>
    if (argc < 4) {
        (void)!write(1, "VERDICT:usage\n", 14);
        return 2;
    }
    target = argv[1];
    setenv("CRFUZZ_PROGRESS", argv[2], 1);
    long workers = atol(argv[3]);

    for (long i = 0; i < workers; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, worker, (void *)i) != 0) {
            (void)!write(1, "VERDICT:thread-failed\n", 22);
            return 1;
        }
    }

    // Let the workers get going before the main thread starts parking, so a
    // measurement taken at the first checkpoint sees genuinely running threads
    // rather than ones that have not started yet.
    struct timespec warm = {.tv_sec = 0, .tv_nsec = 50000000}; // 50ms
    nanosleep(&warm, NULL);

    // CHECKPOINT -- `newfstatat` is the only watched syscall; the main thread
    // parks here and the test gates worker tids by hand.
    for (;;) {
        struct stat st;
        (void)fstatat(AT_FDCWD, target, &st, 0);
        nanosleep(&warm, NULL);
    }
    return 0;
}
