// SPDX-License-Identifier: GPL-2.0
//
// A wakeup in flight when the waker parks (tests/full_readout.rs).
//
// Every thread is pinned to one CPU. A reader blocks on a pipe; the main
// thread parks at `newfstatat`, and once released writes the pipe and parks at
// `newfstatat` again. Sharing one CPU, the woken reader tends to run only once
// the main thread is asleep in that second park; it then stays busy for 50 ms
// before it parks at `newfstatat` too. A readout taken while the reader's
// wakeup is in flight would miss it: a correct second decision holds both.
//
// Built -static for the same reason victim.c is.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int p[2];
static const char *target;

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *reader(void *arg) {
    (void)arg;
    char c;
    struct stat st;
    (void)!read(p[0], &c, 1);
    long end = now_ms() + 50;
    while (now_ms() < end)
        ;
    (void)fstatat(AT_FDCWD, target, &st, 0);
    return NULL;
}

int main(int argc, char **argv) {
    // <target>
    if (argc < 2)
        return 2;
    target = argv[1];
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    pthread_t t;
    if (sched_setaffinity(0, sizeof one, &one) != 0 || pipe(p) != 0 ||
        pthread_create(&t, NULL, reader, NULL) != 0)
        return 1;

    struct stat st;
    (void)fstatat(AT_FDCWD, target, &st, 0);
    (void)!write(p[1], "x", 1);
    (void)fstatat(AT_FDCWD, target, &st, 0);
    pthread_join(t, NULL);
    return 0;
}
