// SPDX-License-Identifier: GPL-2.0
//
// A thread that never comes to rest on its own, for the CPU watchdog
// (tests/full_readout.rs).
//
// The main thread parks at `newfstatat`; a spinner loops on `sched_yield`
// until a flag the main thread sets only after that syscall returns. The
// spinner is never asleep, so no readout completes until the watchdog freezes
// it. Once released, the main thread busy-waits 5 s and reports whether
// the spinner advanced meanwhile ("held" or "ran"), then sets the flag. The
// spinner writes its tid first, so the test can look up its gate.
//
// Built -static for the same reason victim.c is.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile int flag;
static volatile unsigned long spins;
static int out;

static void *spinner(void *arg) {
    (void)arg;
    char buf[32];
    (void)!write(out, buf, snprintf(buf, sizeof buf, "%d\n", gettid()));
    while (!flag) {
        spins++;
        sched_yield();
    }
    return NULL;
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    // <target> <out>
    if (argc < 3)
        return 2;
    out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pthread_t t;
    if (out < 0 || pthread_create(&t, NULL, spinner, NULL) != 0)
        return 1;

    // CHECKPOINT -- held here until the watchdog freezes the spinner.
    struct stat st;
    (void)fstatat(AT_FDCWD, argv[1], &st, 0);

    // Busy, not asleep: the spinner stays frozen until this thread is at rest.
    unsigned long before = spins;
    long end = now_ms() + 5000;
    while (now_ms() < end)
        ;
    (void)!write(out, spins == before ? "held\n" : "ran\n", spins == before ? 5 : 4);
    flag = 1;
    pthread_join(t, NULL);
    return 0;
}
