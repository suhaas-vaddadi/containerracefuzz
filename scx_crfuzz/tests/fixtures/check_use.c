// §8: as root, stat(p) then open(p, O_WRONLY) and write. With "nofollow",
// the open is O_NOFOLLOW: a swapped-in symlink fails it (ELOOP), exit 1.
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
	struct stat st;
	int nofollow = argc > 2 && !strcmp(argv[2], "nofollow");
	if (stat(argv[1], &st) || !S_ISREG(st.st_mode))
		return 2;
	int fd = open(argv[1], O_WRONLY | O_TRUNC | (nofollow ? O_NOFOLLOW : 0));
	if (fd < 0)
		return 1;
	if (write(fd, "written\n", 8) != 8)
		return 3;
	return close(fd) ? 3 : 0;
}
