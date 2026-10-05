// SPDX-License-Identifier: GPL-2.0
//
// The racer half: one generic path substitution.
//
// It renames a pre-made symlink over the victim's path -- one of the small
// fixed action vocabulary design doc section 6.2 describes (symlink swap,
// rename, unlink-and-recreate). renameat is used because it is atomic: the
// path is never momentarily absent, so a lost race shows up as "the victim
// read the benign file", never as a spurious ENOENT that would look like a
// finding but is not.
//
// The path it targets is passed in, never hardcoded -- section 6.2's point
// that the racer's targets come from outside (the mutator) while its action
// vocabulary stays fixed and small.

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void say(const char *s) { (void)!write(1, s, strlen(s)); }

int main(int argc, char **argv) {
    if (argc < 3) {
        say("RACER:usage\n");
        return 2;
    }
    const char *evil = argv[1];   // an existing symlink to the secret
    const char *target = argv[2]; // the path the victim checks and uses

    if (renameat(AT_FDCWD, evil, AT_FDCWD, target) != 0) {
        say("RACER:swap-failed\n");
        return 1;
    }
    say("RACER:swapped\n");
    return 0;
}
