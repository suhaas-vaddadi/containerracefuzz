//! The schedule file, the fixed-schedule policy and finding identity (spec
//! §3.8, M7). Pure: no I/O, so it is tested off-target.

use crate::pos::{EventId, Keys};
use anyhow::{bail, ensure, Context, Result};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    /// Canary `entry` reachable as alice at `at` (a path, or a /proc handle).
    Reached { entry: PathBuf, at: PathBuf },
    /// The token, in a file alice can read.
    Copy { at: PathBuf },
    /// Canary `entry` changed, appeared or vanished.
    Changed { entry: PathBuf },
}

/// `p` with the canary directory as `<canary>`: it differs every run.
pub fn uncanary(p: &Path, canary: &Path) -> Option<PathBuf> {
    p.strip_prefix(canary).ok().map(|rest| Path::new("<canary>").join(rest))
}

/// A finding's identity across runs: the canary directory as `<canary>`, the
/// probed task's /proc handles named by its thread (D4), fd numbers dropped.
/// `task`: the probed event's `(tid, tgid, thread)`; `probe` reads only its
/// `/proc/<tid>/{cwd,root}` and `/proc/<tgid>/fd/N`.
pub fn normalize(f: &Finding, canary: &Path, task: Option<(u32, u32, &str)>) -> Finding {
    let at = |at: &Path| -> PathBuf {
        if let Some(p) = uncanary(at, canary) {
            return p;
        }
        let c: Vec<_> = at.components().collect();
        let n = |i: usize| match c.get(i) {
            Some(Component::Normal(s)) => s.to_str(),
            _ => None,
        };
        if let (Some((tid, tgid, name)), Some(Component::RootDir), Some("proc"), Some(pid)) = (task, c.first(), n(1), n(2).and_then(|s| s.parse::<u32>().ok())) {
            match (n(3), c.len()) {
                (Some(h @ ("cwd" | "root")), 4) if pid == tid => return format!("/proc/{name}/{h}").into(),
                (Some("fd"), 5) if pid == tgid => return format!("/proc/{name}/fd").into(),
                _ => {}
            }
        }
        at.into()
    };
    match f {
        Finding::Reached { entry, at: a } => Finding::Reached { entry: entry.clone(), at: at(a) },
        Finding::Copy { at: a } => Finding::Copy { at: at(a) },
        Finding::Changed { entry } => Finding::Changed { entry: entry.clone() },
    }
}

/// One schedule step (§3.8): release `id`; `mutate`: the mutator fired at its
/// hold in discovery (a failed primitive included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub id: EventId,
    pub mutate: bool,
}

/// A replay left the schedule (D4: divergent). `expected` None: an event was
/// held after the last step; `held` empty: the SUT exited first.
#[derive(Debug)]
pub struct Divergence {
    pub step: usize,
    pub expected: Option<EventId>,
    pub held: Vec<EventId>,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "diverged at step {}: expected {:?}, held {:?}", self.step, self.expected, self.held)
    }
}

impl std::error::Error for Divergence {}

/// Minimization goes on under POS past the one enabled hold `only`;
/// confirmation (None) tolerates no divergence.
pub fn tolerated(only: Option<usize>, d: &Divergence) -> bool {
    only.is_some_and(|k| d.step > k)
}

/// The fixed-schedule policy (§3.5): release the recorded steps in order.
pub struct Fixed<'a> {
    pub steps: &'a [Step],
    /// Steps released so far.
    pub next: usize,
    /// Discovery ended by the deadline: past the last step, release nothing
    /// and let the deadline end the run, as it did.
    pub deadline: bool,
}

impl Fixed<'_> {
    /// Index in `ready` of the next step's event, as `Pos::pick`. Called once
    /// the frontier is complete or the limit expired (D2): a nonempty
    /// frontier without it has left the schedule.
    pub fn pick(&mut self, ready: &[(&EventId, &Keys)]) -> Result<Option<usize>, Divergence> {
        if ready.is_empty() {
            return Ok(None);
        }
        let expected = self.steps.get(self.next).map(|s| &s.id);
        if expected.is_none() && self.deadline {
            return Ok(None);
        }
        match ready.iter().position(|(id, _)| Some(*id) == expected) {
            Some(i) => {
                self.next += 1;
                Ok(Some(i))
            }
            None => Err(Divergence { step: self.next, expected: expected.cloned(), held: ready.iter().map(|(id, _)| (*id).clone()).collect() }),
        }
    }

    /// The SUT exited: every step must have been released.
    pub fn finish(&self) -> Result<(), Divergence> {
        match self.steps.get(self.next) {
            Some(s) => Err(Divergence { step: self.next, expected: Some(s.id.clone()), held: vec![] }),
            None => Ok(()),
        }
    }
}

/// A self-contained schedule file: what discovery ran and found, and its steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    pub seed: u64,
    /// `UID:GID`, as `--attacker`.
    pub attacker: String,
    /// Absolute.
    pub mutator: Option<PathBuf>,
    /// Absolute; run as root before every run to restore the starting
    /// filesystem (§3.9 `layout.sh`).
    pub layout: Option<PathBuf>,
    pub cmd: Vec<String>,
    /// The discovery outcome class (§6), `Outcome`'s variant name.
    pub class: String,
    /// Discovery ended by the deadline, the SUT still running.
    pub deadline: bool,
    /// Discovery's findings, normalized.
    pub findings: BTreeSet<Finding>,
    pub steps: Vec<Step>,
}

/// Bytes outside printable ASCII, space and `%` as `%XX`; the empty string as
/// a lone `%`.
fn esc(b: &[u8]) -> String {
    if b.is_empty() {
        return "%".into();
    }
    b.iter().map(|&c| if c.is_ascii_graphic() && c != b'%' { (c as char).to_string() } else { format!("%{c:02x}") }).collect()
}

fn unesc(s: &str) -> Result<Vec<u8>> {
    let (b, mut out, mut i) = (s.as_bytes(), Vec::new(), 0);
    if s == "%" {
        return Ok(out);
    }
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3).with_context(|| format!("bad escape in {s:?}"))?;
            out.push(u8::from_str_radix(h, 16).with_context(|| format!("bad escape in {s:?}"))?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn esc_path(p: &Path) -> String {
    esc(p.as_os_str().as_bytes())
}

fn unesc_path(s: &str) -> Result<PathBuf> {
    Ok(OsString::from_vec(unesc(s)?).into())
}

fn unesc_str(s: &str) -> Result<String> {
    Ok(String::from_utf8(unesc(s)?)?)
}

impl std::fmt::Display for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "crfuzz-schedule 1\nseed {}\nattacker {}", self.seed, self.attacker)?;
        if let Some(m) = &self.mutator {
            writeln!(f, "mutator {}", esc_path(m))?;
        }
        if let Some(l) = &self.layout {
            writeln!(f, "layout {}", esc_path(l))?;
        }
        writeln!(f, "cmd {}", self.cmd.iter().map(|a| esc(a.as_bytes())).collect::<Vec<_>>().join(" "))?;
        writeln!(f, "outcome {}", self.class)?;
        if self.deadline {
            writeln!(f, "deadline")?;
        }
        for x in &self.findings {
            match x {
                Finding::Reached { entry, at } => writeln!(f, "finding Reached {} {}", esc_path(entry), esc_path(at))?,
                Finding::Copy { at } => writeln!(f, "finding Copy {}", esc_path(at))?,
                Finding::Changed { entry } => writeln!(f, "finding Changed {}", esc_path(entry))?,
            }
        }
        // `mutate thread nr n [path]`, one per POS decision.
        for s in &self.steps {
            write!(f, "step {} {} {} {}", s.mutate as u8, esc(s.id.thread.as_bytes()), s.id.nr, s.id.n)?;
            match &s.id.path {
                Some(p) => writeln!(f, " {}", esc_path(p))?,
                None => writeln!(f)?,
            }
        }
        Ok(())
    }
}

impl std::str::FromStr for Schedule {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        ensure!(lines.next() == Some("crfuzz-schedule 1"), "not a crfuzz schedule (version 1)");
        let mut s = Schedule { seed: 0, attacker: String::new(), mutator: None, layout: None, cmd: vec![], class: String::new(), deadline: false, findings: BTreeSet::new(), steps: vec![] };
        for (i, line) in lines.enumerate() {
            let w: Vec<&str> = line.split(' ').collect();
            let bad = || format!("line {}: {line:?}", i + 2);
            match w[..] {
                ["seed", n] => s.seed = n.parse().with_context(bad)?,
                ["attacker", a] => s.attacker = a.into(),
                ["mutator", m] => s.mutator = Some(unesc_path(m)?),
                ["layout", l] => s.layout = Some(unesc_path(l)?),
                ["cmd", ref args @ ..] => s.cmd = args.iter().map(|a| unesc_str(a)).collect::<Result<_>>()?,
                ["outcome", c] => s.class = c.into(),
                ["deadline"] => s.deadline = true,
                ["finding", "Reached", e, a] => _ = s.findings.insert(Finding::Reached { entry: unesc_path(e)?, at: unesc_path(a)? }),
                ["finding", "Copy", a] => _ = s.findings.insert(Finding::Copy { at: unesc_path(a)? }),
                ["finding", "Changed", e] => _ = s.findings.insert(Finding::Changed { entry: unesc_path(e)? }),
                ["step", m, t, nr, n, ref path @ ..] if path.len() <= 1 => s.steps.push(Step {
                    mutate: m == "1",
                    id: EventId {
                        thread: unesc_str(t)?,
                        nr: nr.parse().with_context(bad)?,
                        path: path.first().map(|p| unesc_path(p)).transpose()?,
                        n: n.parse().with_context(bad)?,
                    },
                }),
                _ => bail!("{}", bad()),
            }
        }
        ensure!(!s.attacker.is_empty() && !s.cmd.is_empty(), "schedule without attacker or cmd");
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_run_identity() {
        let canary = Path::new("/var/lib/crfuzz/canary-4242-1");
        let task = Some((101, 100, "0/1"));
        let r = |at: &str| normalize(&Finding::Reached { entry: "dir".into(), at: at.into() }, canary, task);
        let at = |f: Finding| match f {
            Finding::Reached { at, .. } => at,
            _ => unreachable!(),
        };
        assert_eq!(at(r("/var/lib/crfuzz/canary-4242-1/dir")), Path::new("<canary>/dir"));
        assert_eq!(at(r("/proc/101/cwd")), Path::new("/proc/0/1/cwd"));
        assert_eq!(at(r("/proc/101/root")), Path::new("/proc/0/1/root"));
        assert_eq!(at(r("/proc/100/fd/7")), Path::new("/proc/0/1/fd"));
        // Not the probed task's handle, or not a handle: as is.
        assert_eq!(at(r("/proc/102/cwd")), Path::new("/proc/102/cwd"));
        assert_eq!(at(r("/proc/101/fd/7")), Path::new("/proc/101/fd/7"));
        assert_eq!(at(r("/tmp/a b")), Path::new("/tmp/a b"));
        assert_eq!(at(r("/var/lib/crfuzz/canary-4242-10/x")), Path::new("/var/lib/crfuzz/canary-4242-10/x"));
        let c = normalize(&Finding::Copy { at: "/var/lib/crfuzz/canary-4242-1/file".into() }, canary, None);
        assert_eq!(c, Finding::Copy { at: "<canary>/file".into() });
    }

    #[test]
    fn schedule_round_trip() {
        let id = |thread: &str, path: Option<&[u8]>, n| EventId { thread: thread.into(), nr: 56, path: path.map(|p| OsString::from_vec(p.to_vec()).into()), n };
        let s = Schedule {
            seed: 7,
            attacker: "65534:65534".into(),
            mutator: Some("/tmp/m m.sh".into()),
            layout: Some("/tmp/layout.sh".into()),
            cmd: vec!["/bin/sh".into(), "-c".into(), "echo a%b".into(), "".into()],
            class: "Violation".into(),
            deadline: true,
            findings: [
                Finding::Reached { entry: "".into(), at: "/proc/0/cwd".into() },
                Finding::Copy { at: "<canary>/file".into() },
                Finding::Changed { entry: "dir/sub file".into() },
            ]
            .into(),
            steps: vec![
                Step { id: id("0", Some(b"/tmp/\xff p"), 0), mutate: true },
                Step { id: id("0/1", Some(b""), 2), mutate: false },
                Step { id: id("0", None, 0), mutate: false },
            ],
        };
        assert_eq!(s.to_string().parse::<Schedule>().unwrap(), s);
    }

    #[test]
    fn tolerated_only_past_the_enabled_hold() {
        let d = |step| Divergence { step, expected: None, held: vec![] };
        assert!(!tolerated(None, &d(3)));
        assert!(!tolerated(Some(3), &d(2)));
        assert!(!tolerated(Some(3), &d(3)));
        assert!(tolerated(Some(3), &d(4)));
    }

    #[test]
    fn fixed_past_the_end() {
        let id = EventId { thread: "0".into(), nr: 56, path: None, n: 0 };
        let keys = Keys::default();
        let ready = [(&id, &keys)];
        assert_eq!(Fixed { steps: &[], next: 0, deadline: true }.pick(&ready).unwrap(), None);
        assert_eq!(Fixed { steps: &[], next: 0, deadline: false }.pick(&ready).unwrap_err().expected, None);
    }
}
