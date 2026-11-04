// §10.5: as root, chroot into argv[1], drop to nobody, exit: no exec, so
// nothing needs to exist inside the new root.
#define _GNU_SOURCE
#include <grp.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc < 2 || chroot(argv[1]) || chdir("/") || setgroups(0, 0) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534))
		return 1;
	return 0;
}
