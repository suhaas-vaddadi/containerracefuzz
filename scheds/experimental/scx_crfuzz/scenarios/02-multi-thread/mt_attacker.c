// SPDX-License-Identifier: GPL-2.0
//
// A minimal multithreaded *attacker*: the second kind of process a full
// container startup is run against (the first being runc itself).
//
// Each worker thread hammers a path-touching syscall -- `renameat`, which is in
// the structural checkpoint set -- inside its own scratch subdirectory. The
// point is not what it attacks (that is the mutator's job, deliberately out of
// scope here) but that it is a *thread group*: several OS threads, each parking
// at its own checkpoint, so that holding "the attacker" means holding several
// threads, which is what the `sched_ext` gate exists to do.
//
// Bounded by a wall-clock deadline so the process tree terminates on its own: a
// role that loops forever would keep producing ready-set entries and the engine
// would never see the scenario close.
//
// Built -static for the same reason the other fixtures are: the dynamic loader
// makes path-touching syscalls before main() that would each be a checkpoint.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *root;
static long deadline_ms;
static long renames; // nonzero: exactly this many per thread, and no timer

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *worker(void *arg) {
    long i = (long)arg;
    char dir[512], a[1024], b[1024];
    // Namespaced by pid so two attackers sharing one scratch root do not fight
    // over the same filenames.
    snprintf(dir, sizeof dir, "%s/%d/%ld", root, (int)getpid(), i);
    mkdir(dir, 0755);
    snprintf(a, sizeof a, "%s/a", dir);
    snprintf(b, sizeof b, "%s/b", dir);

    // Seed both names so the first rename swap has something to move.
    int fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
    fd = open(b, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);

    struct timespec nap = {.tv_sec = 0, .tv_nsec = 2000000}; // 2ms
    long end = now_ms() + deadline_ms;
    int flip = 0;
    for (long n = 0; renames ? n < renames : now_ms() < end; n++) {
        // renameat is a structural checkpoint: the thread parks here.
        if (flip)
            (void)!renameat(AT_FDCWD, a, AT_FDCWD, b);
        else
            (void)!renameat(AT_FDCWD, b, AT_FDCWD, a);
        flip = !flip;
        if (!renames)
            nanosleep(&nap, NULL);
    }
    return NULL;
}

int main(int argc, char **argv) {
    // <scratch-dir> <threads> <seconds> [<renames>]
    if (argc < 4) {
        (void)!write(1, "ATTACKER:usage\n", 15);
        return 2;
    }
    root = argv[1];
    long threads = atol(argv[2]);
    deadline_ms = atol(argv[3]) * 1000;
    renames = argc > 4 ? atol(argv[4]) : 0;

    // Create this process's scratch namespace before any thread uses it.
    {
        char parent[512];
        snprintf(parent, sizeof parent, "%s/%d", root, (int)getpid());
        mkdir(parent, 0755);
    }

    pthread_t t[64];
    if (threads > 64) threads = 64;
    for (long i = 0; i < threads; i++) {
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0) {
            (void)!write(1, "ATTACKER:thread-failed\n", 23);
            return 1;
        }
    }
    for (long i = 0; i < threads; i++) pthread_join(t[i], NULL);
    return 0;
}
