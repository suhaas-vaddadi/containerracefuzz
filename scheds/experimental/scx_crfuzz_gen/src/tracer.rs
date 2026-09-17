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
/// appear -- restricted to the syscalls scx_crfuzz's `STRUCTURAL_SYSCALLS`
/// set already declares (design doc section 4.2). `mount`'s third string
/// argument, `filesystemtype`, is deliberately not counted: it names a
/// filesystem driver, not a path.
///
/// `"fstatat"` is deliberately absent: it is not a real syscall name (see
/// `derive::CATEGORY_LOOKUP_ALIASES`'s comment on the same mismatch) --
/// only `"newfstatat"` is ever actually emitted by strace/the kernel, and
/// `strace -e trace=...` rejects `"fstatat"` outright ("invalid system
/// call") wherever the legacy 32-bit stat family isn't in the syscall
/// table, e.g. aarch64. Keeping it here would break `StraceTracer` on
/// exactly the architectures without it, for a name that never appears in
/// output anyway.
const PATH_ARG_COUNT: &[(&str, usize)] = &[
    ("stat", 1),
    ("lstat", 1),
    ("newfstatat", 1),
    ("access", 1),
    ("faccessat", 1),
    ("faccessat2", 1),
    ("readlink", 1),
    ("readlinkat", 1),
    ("openat", 1),
    ("rename", 2),
    ("renameat", 2),
    ("renameat2", 2),
    ("symlink", 2),
    ("symlinkat", 2),
    ("unlink", 1),
    ("unlinkat", 1),
    ("mknod", 1),
    ("mknodat", 1),
    ("mount", 2),
    ("umount", 1),
    ("umount2", 1),
];

/// Parse one `strace -f` output file's text into path-touching events.
///
/// Deliberately does not do general syscall-argument parsing: it finds the
/// syscall name at the start of each line, looks up how many of that
/// syscall's arguments are paths, and takes that many double-quoted strings
/// off the line in order. Every syscall in `PATH_ARG_COUNT` has only path
/// arguments among its quoted strings -- none has a free-text quoted
/// argument that isn't a path -- so this is exact for the syscall set in
/// scope, not an approximation of a general parser.
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
            // e.g. glibc's static-PIE startup does
            // `readlinkat(AT_FDCWD, "/proc/self/exe", ...)` to find its own
            // load bias, and the identical literal string shows up for
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
/// rather than parsed out of a trace: `execve` isn't in `PATH_ARG_COUNT`,
/// and the traced command's own `argv[0]` already carries this information
/// without widening what gets traced.
pub fn derive_comm(cmd: &str) -> Option<String> {
    let program = cmd.split_whitespace().next()?;
    let base = program.rsplit('/').next().unwrap_or(program);
    Some(base.chars().take(15).collect())
}

/// Something that can observe a command's path-touching syscalls. One
/// implementation for now (`StraceTracer`); the seam exists so a future
/// tracer (ptrace directly, or something else) can be swapped in without
/// touching `derive::build_config` or the CLI, both of which are written
/// against `Vec<PathEvent>`, never against strace.
pub trait ProcessTracer {
    fn trace(&self, cmd: &str) -> Result<Vec<PathEvent>>;
}

pub struct StraceTracer;

impl ProcessTracer for StraceTracer {
    fn trace(&self, cmd: &str) -> Result<Vec<PathEvent>> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openat_renameat_and_newfstatat_lines() {
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
                    syscall: "newfstatat".into(),
                    path: "/tmp/crfuzz/target".into()
                },
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
            "readlinkat(AT_FDCWD, \"/proc/self/exe\", \"/bin/victim\", 4096) = 11\n",
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
        let events = StraceTracer
            .trace("/bin/cat /etc/hostname")
            .expect("strace must be installed in the VM");
        assert!(
            events.iter().any(|e| e.path == "/etc/hostname"),
            "expected an openat-family event for /etc/hostname, got {events:?}"
        );
    }
}
