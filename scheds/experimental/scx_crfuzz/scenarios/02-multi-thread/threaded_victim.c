// SPDX-License-Identifier: GPL-2.0
//
// The victim of a check-then-use race, with a sibling thread -- a stand-in for
// the Go runtime's Ms, whose existence is what makes seccomp user-notification
// insufficient on its own.
//
// The main thread runs the same check/use sequence as victim.c, so it stops at
// the same structural checkpoints. The sibling thread does nothing but record
// that it is still running: it appends one byte to a progress file, forever.
//
// That progress file is the whole point. The design doc's Background says a
// role denotes a thread group and "holding a role back means holding every
// thread of that thread group". So while the engine holds this role at a
// checkpoint, the progress file MUST NOT grow. seccomp user-notification holds
// only the thread that made the syscall, so under that backend alone it does
// grow -- which is the gap tests/thread_group_holding.rs exists to measure.
//
// Built -static for the same reason victim.c is: a dynamic loader makes dozens
// of path-touching syscalls before main(), every one of them a checkpoint.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void say(const char *s) { (void)!write(1, s, strlen(s)); }

static const char *progress_path;

// Deliberately NOT a path-touching syscall per iteration: the file is opened
// once, up front, so the sibling's loop makes only write(2) calls. A write to
// an already-open fd is not in the section 4.2 structural set, so the sibling
// never trips a checkpoint of its own. Anything this loop records is therefore
// unambiguously "a thread that should have been held was running".
static void *sibling(void *arg) {
    int fd = *(int *)arg;
    struct timespec nap = {.tv_sec = 0, .tv_nsec = 1000000}; // 1ms
    for (;;) {
        (void)!write(fd, ".", 1);
        nanosleep(&nap, NULL);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        say("VERDICT:usage\n");
        return 2;
    }
    const char *path = argv[1];
    progress_path = argv[2];

    int pfd = open(progress_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pfd < 0) {
        say("VERDICT:progress-open-failed\n");
        return 1;
    }

    pthread_t t;
    if (pthread_create(&t, NULL, sibling, &pfd) != 0) {
        say("VERDICT:thread-failed\n");
        return 1;
    }

    // Give the sibling a moment to get going, so that a test sampling the
    // progress file at the main thread's first checkpoint is measuring a
    // genuinely running thread rather than one that has not started yet.
    struct timespec warmup = {.tv_sec = 0, .tv_nsec = 50000000}; // 50ms
    nanosleep(&warmup, NULL);

    // CHECK -- the main thread's first structural checkpoint.
    struct stat st;
    if (fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        say("VERDICT:check-failed\n");
        return 1;
    }
    if (S_ISLNK(st.st_mode)) {
        say("VERDICT:refused-symlink\n");
        return 0;
    }

    // USE -- by name, the flaw the race exploits.
    int fd = openat(AT_FDCWD, path, O_RDONLY);
    if (fd < 0) {
        say("VERDICT:open-failed\n");
        return 1;
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) n = 0;
    buf[n] = 0;
    for (char *p = buf; *p; p++)
        if (*p == '\n') *p = 0;

    say("VERDICT:read=");
    say(buf);
    say("\n");
    return 0;
}
