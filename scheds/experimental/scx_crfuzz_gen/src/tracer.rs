// SPDX-License-Identifier: GPL-2.0
//
// Turns strace(1) output into PathEvents, and (further down this file)
// actually invokes strace against a role's command.

use crate::derive::PathEvent;
use anyhow::Context;
use anyhow::Result;
use std::process::Command;
use std::process::Stdio;

/// How many of a syscall's arguments are path-shaped, in the order they
/// appear -- exactly the syscalls in scx_crfuzz's `STRUCTURAL_SYSCALLS`
/// (design doc section 4.2), the use-shaped ones. Check-shaped syscalls are
/// not traced: `derive::build_config` would drop them anyway, and a race
/// always has a use on the contended path, so they add no contention signal.
///
/// `mount`'s third string argument, `filesystemtype`, is deliberately not
/// counted: it names a filesystem driver, not a path. `setxattr` and friends
/// print the attribute name after the path, and `execve` its argv strings,
/// which the count leaves out.
/// `move_mount` and `open_tree` often pass `""` with `AT_EMPTY_PATH`; an empty
/// path matches nothing on another role, so it is harmless.
///
/// The legacy x86_64 names (`open`, `mkdir`, `chmod`, ...) have no aarch64
/// syscall number, but strace still accepts them there, from its 32-bit arm
/// table (checked: strace 7.2, aarch64), so listing them does not break
/// `-e trace=`.
const PATH_ARG_COUNT: &[(&str, usize)] = &[
    ("openat", 1),
    ("openat2", 1),
    ("open", 1),
    ("creat", 1),
    ("execve", 1),
    ("execveat", 1),
    ("mkdirat", 1),
    ("unlinkat", 1),
    ("renameat", 2),
    ("renameat2", 2),
    ("linkat", 2),
    ("symlinkat", 2),
    ("mknodat", 1),
    ("mkdir", 1),
    ("rmdir", 1),
    ("unlink", 1),
    ("rename", 2),
    ("link", 2),
    ("symlink", 2),
    ("mknod", 1),
    ("fchmodat", 1),
    ("fchmodat2", 1),
    ("fchownat", 1),
    ("truncate", 1),
    ("setxattr", 1),
    ("lsetxattr", 1),
    ("removexattr", 1),
    ("lremovexattr", 1),
    ("utimensat", 1),
    ("chmod", 1),
    ("chown", 1),
    ("lchown", 1),
    ("utime", 1),
    ("utimes", 1),
    ("futimesat", 1),
    ("mount", 2),
    ("umount2", 1),
    ("pivot_root", 2),
    ("chroot", 1),
    ("open_tree", 1),
    ("move_mount", 2),
    ("mount_setattr", 1),
    ("fspick", 1),
    ("chdir", 1),
];

/// Parse one `strace -f` output file's text into path-touching events.
///
/// Deliberately does not do general syscall-argument parsing: it finds the
/// syscall name at the start of each line, looks up how many of that
/// syscall's arguments are paths, and takes that many double-quoted strings
/// off the line in order. Every syscall in `PATH_ARG_COUNT` prints its path
/// arguments as its *first* quoted strings -- any other quoted argument (an
/// xattr name, `mount`'s filesystem type) comes after them -- so this is
/// exact for the syscall set in scope, not an approximation of a general
/// parser.
pub fn parse_strace_output(text: &str) -> Vec<PathEvent> {
    let mut events = Vec::new();
    for line in text.lines() {
        let Some(paren) = line.find('(') else {
            continue;
        };
        // `strace -f` prefixes some or all lines with a pid marker once
        // more than one process/thread could be involved: `[pid NNNN] `
        // for follower processes on some strace versions, or a bare
        // `NNNN ` on every line -- even the sole, non-forking process --
        // on others (observed: strace 7.2). Either way, the syscall name
        // is the last whitespace-separated token before the '(', so take
        // that rather than assuming the whole trimmed prefix is the name.
        // Which pid a checkpoint came from doesn't matter here -- only
        // which role's *command* was traced does, and that's a whole
        // separate invocation per role.
        let before_paren = line[..paren].trim();
        let syscall = before_paren
            .split_whitespace()
            .last()
            .unwrap_or(before_paren);
        let Some(&(_, n_paths)) = PATH_ARG_COUNT.iter().find(|(name, _)| *name == syscall) else {
            continue;
        };

        let paths = extract_quoted_strings(&line[paren..]);
        for path in paths.into_iter().take(n_paths) {
            // `/proc/self/...` always names the calling process itself:
            // e.g. runtimes open `/proc/self/maps`, `/proc/self/fd/N` or
            // `/proc/self/exe` about themselves (glibc's static-PIE startup
            // `readlinkat`s the last, though that call is no longer traced),
            // and the identical literal string shows up for
            // every traced role without ever naming a real, shared
            // resource -- it's self-referential by construction, not
            // shared. Left in, it would make the contention filter see
            // every pair of roles as "contending" on `/proc/self/exe`,
            // which is never the TOCTOU signal this tool looks for.
            // Filtered at the source rather than in the (pure,
            // role-agnostic) contention filter itself, since this is about
            // what a path *is*, not about how many roles touched it.
            //
            // Deliberately narrower than all of `/proc/`: a path like
            // `/proc/<other-pid>/fd/N` or `/proc/<other-pid>/root` names a
            // *different* process and could be a genuine cross-role
            // shared resource -- exactly the kind of `/proc`-based
            // symlink race this tool might otherwise be able to surface.
            // Only the self-referential `/proc/self/` form is noise.
            if path.starts_with("/proc/self/") {
                continue;
            }
            events.push(PathEvent {
                syscall: syscall.to_string(),
                path,
            });
        }
    }
    events
}

/// Extract every double-quoted string from `s`, unescaped. Good enough for
/// strace's own quoting (`\"`, `\\`, `\n`, ...) because we only ever care
/// about the string's content, never about distinguishing e.g. a literal
/// backslash from an escaped one.
fn extract_quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut cur = String::new();
        while let Some(&next) = chars.peek() {
            chars.next();
            match next {
                '"' => break,
                '\\' => {
                    if let Some(&escaped) = chars.peek() {
                        cur.push(escaped);
                        chars.next();
                    }
                }
                other => cur.push(other),
            }
        }
        out.push(cur);
    }
    out
}

/// The `comm` a kernel would report for this role's command -- the executed
/// binary's basename, truncated to approximate the kernel's `TASK_COMM_LEN -
/// 1` (15) byte truncation of `/proc/<pid>/comm`, via a 15-*char* truncation
/// here rather than a byte-wise one. Exact for ASCII basenames (the
/// realistic case -- traced role binaries are essentially always
/// ASCII-named), but could diverge from the kernel's byte count for a
/// hypothetical multi-byte UTF-8 basename. Derived from the command itself
/// rather than parsed out of a trace: `execve` is traced, but the traced
/// command's own `argv[0]` already carries this information, with no need
/// to pick the role's first exec out of `strace -f` output.
pub fn derive_comm(cmd: &str) -> Option<String> {
    let program = cmd.split_whitespace().next()?;
    let base = program.rsplit('/').next().unwrap_or(program);
    Some(base.chars().take(15).collect())
}

/// Observe a command's path-touching syscalls under strace.
///
/// `derive::build_config` and the CLI consume `Vec<PathEvent>`, never strace
/// itself, so a different tracer can replace this function without touching
/// them.
pub fn trace(cmd: &str) -> Result<Vec<PathEvent>> {
    let out = tempfile::NamedTempFile::new().context("creating strace output tempfile")?;
    let syscalls: Vec<&str> = PATH_ARG_COUNT.iter().map(|(name, _)| *name).collect();
    let mut words = cmd.split_whitespace();
    let program = words.next().context("empty role command")?;
    let args: Vec<&str> = words.collect();

    let status = Command::new("strace")
        .arg("-f")
        .arg("-e")
        .arg(format!("trace={}", syscalls.join(",")))
        .arg("-o")
        .arg(out.path())
        .arg("--")
        .arg(program)
        .args(&args)
        .stdout(Stdio::null())
        .status()
        .context("spawning strace -- is it installed?")?;

    // `strace -f -o file -- prog args` exits with the TRACED PROGRAM's
    // exit status (or 128+signal), not a status specific to strace's
    // own failure to instrument -- so a role command that legitimately
    // exits non-zero must not, on its own, discard an otherwise-usable
    // trace. The real error signal is an empty output file: that only
    // happens when strace never produced any trace data at all, e.g.
    // it couldn't exec the program, or ptrace was denied before
    // anything ran.
    let text = std::fs::read_to_string(out.path()).context("reading strace output file")?;
    if text.is_empty() && !status.success() {
        anyhow::bail!(
                "strace produced no output while tracing `{cmd}` (exited {status}) -- is strace installed and able to trace this program?"
            );
    }
    Ok(parse_strace_output(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_use_shaped_lines_and_ignores_check_shaped_ones() {
        let text = concat!(
            "newfstatat(AT_FDCWD, \"/tmp/crfuzz/target\", {st_mode=S_IFREG|0644, st_size=7, ...}, AT_SYMLINK_NOFOLLOW) = 0\n",
            "openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY) = 3\n",
            "renameat(AT_FDCWD, \"/tmp/crfuzz/evil\", AT_FDCWD, \"/tmp/crfuzz/target\") = 0\n",
        );
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![
                PathEvent {
                    syscall: "openat".into(),
                    path: "/tmp/crfuzz/target".into()
                },
                PathEvent {
                    syscall: "renameat".into(),
                    path: "/tmp/crfuzz/evil".into()
                },
                PathEvent {
                    syscall: "renameat".into(),
                    path: "/tmp/crfuzz/target".into()
                },
            ]
        );
    }

    #[test]
    fn pid_prefixed_lines_from_follow_forks_are_still_parsed() {
        let text = "[pid 4821] openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY) = 3\n";
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![PathEvent {
                syscall: "openat".into(),
                path: "/tmp/crfuzz/target".into()
            }]
        );
    }

    #[test]
    fn lines_for_untracked_syscalls_are_ignored() {
        let text = "write(1, \"VERDICT:read=SECRET\\n\", 20) = 20\n";
        assert_eq!(parse_strace_output(text), vec![]);
    }

    #[test]
    fn unfinished_and_resumed_call_lines_do_not_double_count_or_panic() {
        let text = concat!(
            "openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY <unfinished ...>\n",
            "<... openat resumed>) = 3\n",
        );
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![PathEvent {
                syscall: "openat".into(),
                path: "/tmp/crfuzz/target".into()
            }]
        );
    }

    #[test]
    fn bare_pid_prefixed_lines_are_parsed_the_same_as_bracketed_ones() {
        // Some strace versions (observed: 7.2) prefix every line with a
        // bare "PID " under -f, even for a single non-forking process,
        // rather than reserving "[pid NNNN] " for followers only.
        let text = "233759 openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY) = 3\n";
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![PathEvent {
                syscall: "openat".into(),
                path: "/tmp/crfuzz/target".into()
            }]
        );
    }

    #[test]
    fn proc_self_paths_are_filtered_as_never_a_real_shared_resource() {
        // glibc's static-PIE startup does this on every traced binary to
        // find its own load bias -- identical for every role, never an
        // actual shared path in the TOCTOU sense the contention filter
        // looks for.
        let text = concat!(
            "openat(AT_FDCWD, \"/proc/self/exe\", O_RDONLY) = 3\n",
            "openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY) = 3\n",
        );
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![PathEvent {
                syscall: "openat".into(),
                path: "/tmp/crfuzz/target".into()
            }]
        );
    }

    #[test]
    fn only_the_leading_quoted_strings_are_taken_as_paths() {
        let text = concat!(
            "setxattr(\"/tmp/crfuzz/target\", \"user.x\", \"v\", 1, 0) = 0\n",
            "mount(\"/tmp/crfuzz/src\", \"/tmp/crfuzz/dst\", \"tmpfs\", 0, NULL) = 0\n",
        );
        let paths: Vec<String> = parse_strace_output(text)
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(
            paths,
            vec!["/tmp/crfuzz/target", "/tmp/crfuzz/src", "/tmp/crfuzz/dst"]
        );
    }

    #[test]
    fn derive_comm_strips_directory_components() {
        assert_eq!(
            derive_comm("./victim /tmp/crfuzz/target").as_deref(),
            Some("victim")
        );
    }

    #[test]
    fn derive_comm_truncates_to_the_kernel_comm_length() {
        assert_eq!(
            derive_comm("./containerd-shim-runc-v2 --arg").as_deref(),
            Some("containerd-shim")
        );
    }

    #[test]
    fn derive_comm_rejects_an_empty_command() {
        assert_eq!(derive_comm(""), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn strace_tracer_observes_a_real_openat_call() {
        let events = trace("/bin/cat /etc/hostname").expect("strace must be installed in the VM");
        assert!(
            events.iter().any(|e| e.path == "/etc/hostname"),
            "expected an openat-family event for /etc/hostname, got {events:?}"
        );
    }
}
