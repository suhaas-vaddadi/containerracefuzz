// SPDX-License-Identifier: GPL-2.0
//
// The victim half of a check-then-use race.
//
// It checks a path (fstatat with AT_SYMLINK_NOFOLLOW -- "is this a plain file,
// not a symlink?") and then, if satisfied, uses that same path by name
// (openat). Between those two syscalls the path can be swapped for a symlink
// pointing somewhere the victim would never have agreed to open. That gap is
// the entire bug class (design doc section 4.1, Class A).
//
// Deliberately: no stdio, no locale, no dynamic loader. Built -static and
// writing via write(2), so the ONLY path-touching syscalls it makes are the
// two that matter. Anything else in a trace is the engine's problem, not
// noise from this program.

#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void say(const char *s) { (void)!write(1, s, strlen(s)); }

int main(int argc, char **argv) {
    if (argc < 2) {
        say("VERDICT:usage\n");
        return 2;
    }
    const char *path = argv[1];

    // CHECK
    struct stat st;
    if (fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        say("VERDICT:check-failed\n");
        return 1;
    }
    if (S_ISLNK(st.st_mode)) {
        // The check did its job: refuse a symlink outright.
        say("VERDICT:refused-symlink\n");
        return 0;
    }

    // USE -- by name, not by the descriptor the check was about. This is the
    // flaw the race exploits, and it is exactly what the real CVEs do.
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
