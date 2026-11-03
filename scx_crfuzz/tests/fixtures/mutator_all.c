// Deterministic filesystem TOCTOU mutator for scx_crfuzz (development only).
//
// Model runc's symlink-exchange mount bug (CVE-2021-30465), create-time
// dangling links, and subpath/ancestor rebinding (Kubernetes CVE-2021-25741).
// Only the SUT follows a link into the canary: direct renames or links into
// the 0700 canary fail as alice, and FIFOs merely hang the held SUT.
//
// argv[1] is the held path; CRFUZZ_CANARY is required. Also honors CRFUZZ_SCOPE,
// CRFUZZ_TARGET, CRFUZZ_ENTRY, CRFUZZ_PRIMITIVE ("swap", "dangling", "pivot",
// or "all"), CRFUZZ_SEED and CRFUZZ_LOG. The default entry matches the held
// object's type: "dir" for an existing directory, "file" otherwise.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

static char path[PATH_MAX], full[PATH_MAX], scope[PATH_MAX];
static char canary[PATH_MAX], entry[PATH_MAX];
static unsigned long seed;
static int serial;

static int join(char *out, size_t n, const char *a, const char *b) {
	if (snprintf(out, n, "%s/%s", a, b) < (int)n)
		return 0;
	errno = ENAMETOOLONG;
	return -1;
}

static void note(const char *primitive, int error) {
	const char *log = getenv("CRFUZZ_LOG");
	FILE *f = log ? fopen(log, "a") : NULL;
	if (f) {
		fprintf(f, "%s\t%s\t%s\n", primitive, path, error ? strerror(error) : "ok");
		fclose(f);
	}
}

static int parent(char *p) {
	char *slash = strrchr(p, '/');
	if (!slash || !p[1])
		return -1;
	slash == p ? (p[1] = 0) : (*slash = 0);
	return 0;
}

static int append(char *out, const char *part) {
	size_t n = strlen(out), len = strlen(part);
	if (n + (n > 1) + len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (n > 1)
		out[n++] = '/';
	memcpy(out + n, part, len + 1);
	return 0;
}

static int within(const char *p, int strict) {
	if (!strcmp(scope, "/"))
		return p[0] == '/' && (!strict || p[1]);
	size_t n = strlen(scope);
	if (strncmp(p, scope, n))
		return 0;
	return strict ? p[n] == '/' && p[n + 1] : !p[n] || p[n] == '/';
}

// Lexical, not realpath: dangling paths work and the final symlink is not
// followed. Collapsing ".." also keeps a scoped mutation inside its scope.
static int normalize(char *out, const char *in) {
	char raw[PATH_MAX * 2], cwd[PATH_MAX], *save, *part;
	if (in[0] == '/') {
		if (snprintf(raw, sizeof raw, "%s", in) >= (int)sizeof raw) {
			errno = ENAMETOOLONG;
			return -1;
		}
	} else if (!getcwd(cwd, sizeof cwd) || join(raw, sizeof raw, cwd, in) < 0) {
		return -1;
	}
	strcpy(out, "/");
	for (part = strtok_r(raw, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
		if (!strcmp(part, "."))
			continue;
		if (!strcmp(part, "..")) {
			parent(out);
			continue;
		}
		if (append(out, part) < 0)
			return -1;
	}
	return 0;
}

static int sibling(char *out, const char *at) {
	if (snprintf(out, PATH_MAX, "%s.crfuzz.%d.%d", at, (int)getpid(), serial++) < PATH_MAX)
		return 0;
	errno = ENAMETOOLONG;
	return -1;
}

static void discard(const char *p) {
	int saved = errno;
	if (unlink(p) < 0)
		rmdir(p);
	errno = saved;
}

// Exchange replaces even a directory with a symlink. The old object moves to
// the staging name; never recursively delete it.
static int exchange(char *staged, const char *dst) {
	if (syscall(SYS_renameat2, AT_FDCWD, staged, AT_FDCWD, dst, RENAME_EXCHANGE) == 0) {
		discard(staged);
		return 0;
	}
	int saved = errno;
	if ((saved == ENOENT || saved == ENOSYS || saved == EINVAL) && rename(staged, dst) == 0)
		return 0;
	if (errno != saved)
		saved = errno;
	discard(staged);
	errno = saved;
	return -1;
}

static int symlink_exchange(const char *dst, const char *target) {
	char tmp[PATH_MAX];
	if (sibling(tmp, dst) < 0 || symlink(target, tmp) < 0)
		return -1;
	return exchange(tmp, dst);
}

static int p_swap(void) { return symlink_exchange(full, entry); }
static int p_dangling(void) {
	char missing[PATH_MAX];
	return join(missing, sizeof missing, canary, "missing") < 0 ? -1 : symlink_exchange(full, missing);
}

// If the suffix names a canary entry, link its ancestor directly, leaving no
// final symlink for O_NOFOLLOW to catch. Otherwise exchange the ancestor for a
// shadow tree ending in that link. Seed high bits select the ancestor's height.
static int p_pivot(void) {
	char at[PATH_MAX], scan[PATH_MAX];
	snprintf(at, sizeof at, "%s", full);
	if (parent(at) < 0 || !strcmp(at, "/") || (scope[0] && !within(at, 1))) {
		errno = EPERM;
		return -1;
	}
	int levels = 1;
	snprintf(scan, sizeof scan, "%s", at);
	if (scope[0])
		while (parent(scan) == 0 && within(scan, 1))
			levels++;
	for (unsigned long n = scope[0] ? (seed >> 32) % (unsigned long)levels : 0; n; n--)
		parent(at);

	const char *rest = full + strlen(at);
	if (rest[0] == '/' && !strcmp(rest + 1, entry + strlen(canary) + 1))
		return symlink_exchange(at, canary);

	char staged[PATH_MAX], cur[PATH_MAX], suffix[PATH_MAX], *save, *part, *next;
	if (sibling(staged, at) < 0 || mkdir(staged, 0700) < 0)
		return -1;
	snprintf(cur, sizeof cur, "%s", staged);
	snprintf(suffix, sizeof suffix, "%s", rest);
	for (part = strtok_r(suffix, "/", &save); part; part = next) {
		next = strtok_r(NULL, "/", &save);
		if (append(cur, part) < 0 || (next && mkdir(cur, 0700) < 0))
			return -1;
		if (!next) {
			if (symlink(entry, cur) < 0)
				return -1;
			return exchange(staged, at);
		}
	}
	errno = EINVAL;
	return -1;
}

static const struct { const char *name; int (*run)(void); } primitives[] = {
	{"swap", p_swap}, {"dangling", p_dangling}, {"pivot", p_pivot},
};

static void run(int i) {
	errno = 0;
	int rc = primitives[i].run();
	int saved = errno;
	note(primitives[i].name, rc ? (saved ? saved : EIO) : 0);
}

int main(int argc, char **argv) {
	if (argc < 2 || !argv[1][0] || strlen(argv[1]) >= PATH_MAX || normalize(full, argv[1]) < 0)
		return 0;
	snprintf(path, sizeof path, "%s", argv[1]);

	const char *s = getenv("CRFUZZ_SCOPE"), *target = getenv("CRFUZZ_TARGET");
	if (s && *s) {
		if (normalize(scope, s) < 0 || !within(full, 0))
			return 0;
	} else if (target && *target) {
		char wanted[PATH_MAX];
		if (normalize(wanted, target) < 0 || strcmp(full, wanted))
			return 0;
	} else {
		char dir[PATH_MAX];
		snprintf(dir, sizeof dir, "%s", full);
		if (parent(dir) < 0 || access(dir, W_OK) < 0)
			return 0;
	}

	const char *c = getenv("CRFUZZ_CANARY");
	if (!c || !*c || snprintf(canary, sizeof canary, "%s", c) >= (int)sizeof canary)
		return 0;
	const char *en = getenv("CRFUZZ_ENTRY");
	struct stat st;
	if (!en || !*en)
		en = stat(full, &st) == 0 && S_ISDIR(st.st_mode) ? "dir" : "file";
	if (join(entry, sizeof entry, canary, en) < 0)
		return 0;

	const char *which = getenv("CRFUZZ_PRIMITIVE"), *value = getenv("CRFUZZ_SEED");
	seed = value ? strtoul(value, NULL, 10) : 0;
	int n = (int)(sizeof primitives / sizeof primitives[0]);
	if (which && !strcmp(which, "all")) {
		for (int i = 0; i < n; i++)
			run(i);
	} else if (which && *which) {
		for (int i = 0; i < n; i++)
			if (!strcmp(which, primitives[i].name))
				run(i);
	} else {
		run(seed % (unsigned long)n);
	}
	return 0;
}
