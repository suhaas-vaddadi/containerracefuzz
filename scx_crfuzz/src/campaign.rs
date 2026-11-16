//! A campaign: seeds swept into DIR, `--jobs` at a time. Its files, the
//! resume from them, the totals and what the terminal shows.

use crate::run::{self, Confirmed, Runner};
use anyhow::{ensure, Context, Result};
use scx_crfuzz::engine::{self, Decision};
use scx_crfuzz::name::EventId;
use scx_crfuzz::names;
use scx_crfuzz::oracle::Class;
use scx_crfuzz::schedule::{self, Config, Dedup, Schedule};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::hash::BuildHasher;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `run`'s arguments.
pub struct Campaign {
    pub dir: PathBuf,
    pub cfg: Config,
    /// Seeds `first..first + seeds`; no `seeds`: until stopped.
    pub first: u64,
    pub seeds: Option<u64>,
    /// `--time`: no run starts once that much has passed.
    pub time: Option<Duration>,
    pub jobs: usize,
    pub resume: bool,
    pub verbose: bool,
}

/// What a seed's windows came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    /// Every window valid, mutated and no Violation.
    Safe,
    /// A window's Violation.
    Unsafe,
    /// A window invalid or unmutated, or the baseline invalid.
    Incomplete,
    /// No mutator or no target: the seed is one unmutated run, window 0.
    NoWindows,
}

names!(Verdict { Safe = "safe", Unsafe = "unsafe", Incomplete = "incomplete", NoWindows = "no windows" });

const VERDICTS: [Verdict; 4] = [Verdict::Safe, Verdict::Unsafe, Verdict::Incomplete, Verdict::NoWindows];

/// What became of a window's Violation; `None` for any other class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    None,
    /// Confirmed, and no finding so far matches it.
    New,
    /// Matches a finding (`Dedup::repeated_by`): only counted.
    Repeat,
    Unconfirmed,
    /// Its confirmation failed.
    Invalid,
}

names!(Status { None = "-", New = "new", Repeat = "repeat", Unconfirmed = "unconfirmed", Invalid = "invalid" });

/// A row of `runs.tsv`: one run of a seed.
struct Row {
    seed: u64,
    /// None: the seed's baseline, recorded only when invalid.
    window: Option<usize>,
    class: Class,
    status: Status,
    finding: Option<usize>,
    decisions: usize,
    partial: usize,
    secs: f64,
    note: String,
}

const HEAD: &str = "seed\twindow\tclass\tstatus\tfinding\tdecisions\tpartial\tsecs\tnote";

impl std::fmt::Display for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let opt = |o: Option<usize>| o.map_or("-".into(), |v| v.to_string());
        let Row { seed, class, status, decisions, partial, secs, note, .. } = self;
        write!(f, "{seed}\t{}\t{class}\t{status}\t{}\t{decisions}\t{partial}\t{secs:.3}\t{note}", opt(self.window), opt(self.finding))
    }
}

impl std::str::FromStr for Row {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let opt = |s: &str| if s == "-" { Ok(None) } else { s.parse().map(Some) };
        let c: Vec<&str> = s.split('\t').collect();
        ensure!(c.len() == 9, "not 9 columns");
        Ok(Row { seed: c[0].parse()?, window: opt(c[1])?, class: c[2].parse()?, status: c[3].parse()?, finding: opt(c[4])?, decisions: c[5].parse()?, partial: c[6].parse()?, secs: c[7].parse()?, note: c[8].into() })
    }
}

/// The campaign's totals, behind one lock for every worker.
struct Tally {
    tsv: File,
    seeds: File,
    total: u64,
    invalid: u64,
    decisions: usize,
    partial: usize,
    time: Duration,
    /// ponytail: 64-bit hashes of the canonical orders; a collision only undercounts.
    orders: HashSet<u64>,
    unmutated: u64,
    classes: BTreeMap<Class, u64>,
    verdicts: BTreeMap<Verdict, u64>,
    /// A baseline has ended: the plan line is out.
    planned: bool,
}

impl Tally {
    /// A row into the totals.
    fn count(&mut self, r: &Row) -> Result<()> {
        *self.classes.entry(r.class).or_default() += 1;
        self.invalid += (r.class == Class::Invalid || r.status == Status::Invalid) as u64;
        if r.window.is_some() {
            self.total += 1;
            self.decisions += r.decisions;
            self.partial += r.partial;
            self.time += Duration::try_from_secs_f64(r.secs)?;
            // Its target never came up: the run says nothing about the mutator.
            self.unmutated += r.note.starts_with("unmutated") as u64;
        }
        Ok(())
    }

    /// Seeds ended.
    fn done(&self) -> u64 {
        self.verdicts.values().sum()
    }
}

/// A worker's stdout: at --jobs 1 straight through, else kept in `buf`.
struct Out {
    live: bool,
    buf: Vec<u8>,
}

impl Write for Out {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.live { std::io::stdout().write(b) } else { self.buf.write(b) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

fn hms(s: f64) -> String {
    let s = s.round() as u64;
    if s >= 3600 { format!("{}h{:02}m", s / 3600, s / 60 % 60) } else if s >= 60 { format!("{}m{:02}s", s / 60, s % 60) } else { format!("{s}s") }
}

fn hold(thread: &str, nr: i64, p: &Option<PathBuf>) -> String {
    format!("({thread} {nr} {})", p.as_deref().map_or("-".into(), |p| p.display().to_string()))
}

fn partial(log: &[Decision]) -> usize {
    log.iter().filter(|d| d.partial).count()
}

/// A run's partial order: a hash of its canonical member.
fn order(log: &[Decision]) -> u64 {
    let canon = schedule::canonical(&log.iter().map(|d| (&d.id, &d.keys)).collect::<Vec<_>>());
    std::hash::BuildHasherDefault::<std::hash::DefaultHasher>::default().hash_one(canon)
}

/// A file of DIR's, "" if missing (none when not resuming).
fn read(p: &Path) -> Result<String> {
    match fs::read_to_string(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        r => r.with_context(|| p.display().to_string()),
    }
}

struct Sweep<'a> {
    c: &'a Campaign,
    r: &'a Runner,
    /// Seeds with a verdict from an earlier session: skipped.
    complete: BTreeMap<u64, Verdict>,
    tally: Mutex<Tally>,
    /// The findings, each with its `seed:k` lines. Dedup, confirm and push
    /// under one lock: two workers on one new bug give a finding and a
    /// repeat, never two findings.
    found: Mutex<Vec<(Dedup, Vec<String>)>>,
    next: AtomicU64,
    jobs: usize,
    started: Instant,
    /// On a terminal and without -v, a progress line over seeds on stderr
    /// below the per-run lines; cleared before anything prints to stdout.
    tty: bool,
}

impl<'a> Sweep<'a> {
    /// DIR as an earlier session left it: a seed is complete once it has a
    /// verdict; what the others left goes.
    fn open(c: &'a Campaign, r: &'a Runner) -> Result<Self> {
        let dir = &c.dir;
        let seeds_tsv = read(&dir.join("seeds.tsv"))?;
        let mut complete = BTreeMap::new();
        let verdict_rows: Vec<&str> = seeds_tsv
            .lines()
            .skip(1)
            .filter(|l| l.split_once('\t').and_then(|(s, v)| Some((s.parse::<u64>().ok()?, v.parse::<Verdict>().ok()?))).is_some_and(|(s, v)| complete.insert(s, v).is_none()))
            .collect();
        let of_complete = |l: &str, sep: char| l.split(sep).next().and_then(|s| s.parse().ok()).is_some_and(|s: u64| complete.contains_key(&s));
        let runs_tsv = read(&dir.join("runs.tsv"))?;
        let rows: Vec<&str> = runs_tsv.lines().skip(1).filter(|l| of_complete(l, '\t')).collect();
        for e in fs::read_dir(dir.join("runs"))? {
            let e = e?;
            if !e.file_name().to_str().is_some_and(|s| of_complete(s, '/')) {
                fs::remove_dir_all(e.path()).with_context(|| e.path().display().to_string())?;
            }
        }
        // Rewritten whole (then renamed into place), appended to from then on.
        let table = |name: &str, head: &str, rows: &[&str]| -> Result<File> {
            let (p, tmp) = (dir.join(name), dir.join(format!("{name}.tmp")));
            fs::write(&tmp, rows.iter().fold(format!("{head}\n"), |s, r| s + r + "\n"))?;
            fs::rename(&tmp, &p)?;
            Ok(File::options().append(true).open(&p)?)
        };
        // The totals so far (but the partial orders: their keys are not on disk).
        let mut tally = Tally {
            tsv: table("runs.tsv", HEAD, &rows)?,
            seeds: table("seeds.tsv", "seed\tverdict", &verdict_rows)?,
            total: 0,
            invalid: 0,
            decisions: 0,
            partial: 0,
            time: Duration::ZERO,
            orders: HashSet::new(),
            unmutated: 0,
            classes: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            planned: false,
        };
        // Every complete seed stays on disk, but only this range's count
        // (`--first-seed` may move on a resume).
        let range = c.first..c.seeds.map_or(u64::MAX, |n| c.first + n);
        for v in complete.range(range.clone()).map(|e| e.1) {
            *tally.verdicts.entry(*v).or_default() += 1;
        }
        for row in &rows {
            let bad = || format!("{}: bad row {row:?}", dir.join("runs.tsv").display());
            let row: Row = row.parse().with_context(bad)?;
            if range.contains(&row.seed) {
                tally.count(&row).with_context(bad)?;
            }
        }
        // The findings so far, their seed:k lines of complete seeds only: a
        // repeat counts against them.
        let mut found = Vec::new();
        for n in 1.. {
            let f = dir.join(format!("findings/{n}"));
            if !f.exists() {
                break;
            }
            let s: Schedule = read(&f.join("schedule"))?.parse().with_context(|| f.display().to_string())?;
            let guilty = match read(&f.join("guilty"))?.trim() {
                "-" => None,
                g => {
                    let id = &g.parse().ok().and_then(|g: usize| s.steps.get(g)).with_context(|| format!("{}/guilty: not a step", f.display()))?.id;
                    Some((id.thread.clone(), id.nr, id.path.clone()))
                }
            };
            let seeds: Vec<String> = read(&f.join("seeds"))?.lines().filter(|l| of_complete(l, ':')).map(String::from).collect();
            fs::write(f.join("seeds"), seeds.iter().map(|s| format!("{s}\n")).collect::<String>())?;
            found.push((Dedup { guilty, findings: s.findings }, seeds));
        }
        complete.retain(|s, _| range.contains(s));
        // No worker (or private copy) without a seed.
        let jobs = c.seeds.map_or(c.jobs, |n| n.min(c.jobs as u64) as usize);
        let tty = !c.verbose && std::io::stderr().is_terminal();
        Ok(Sweep { c, r, complete, tally: Mutex::new(tally), found: Mutex::new(found), next: AtomicU64::new(0), jobs, started: Instant::now(), tty })
    }

    fn clear(&self) {
        if self.tty {
            eprint!("\r\x1b[K");
        }
    }

    fn bar(&self, t: &Tally) {
        if !self.tty {
            return;
        }
        let (done, elapsed) = (t.done(), self.started.elapsed());
        let head = match self.c.seeds {
            Some(n) => {
                let w = 24;
                let fill = (done.min(n) * w / n) as usize;
                // From this session's seeds (confirms included); the plan line has the first guess.
                let ran = done.saturating_sub(self.complete.len() as u64);
                let eta = if ran == 0 { "?".into() } else { hms(elapsed.as_secs_f64() / ran as f64 * n.saturating_sub(done) as f64) };
                format!("[{}{}] {done}/{n} seeds  ETA {eta}", "#".repeat(fill), ".".repeat(w as usize - fill))
            }
            None => {
                let left = self.c.time.map(|l| format!("  {} left", hms(l.saturating_sub(elapsed).as_secs_f64()))).unwrap_or_default();
                format!("{done} seeds  {} elapsed{left}", hms(elapsed.as_secs_f64()))
            }
        };
        let counts: Vec<String> = t.classes.iter().map(|(c, k)| format!("{c} {k}")).collect();
        eprint!("\r{head}  {}\x1b[K", counts.join("  "));
    }

    /// A line of a seed's: at --jobs 1 as it comes; else the seed's lines
    /// print as one block when it ends (`show`'s `end`).
    fn say(&self, w: &mut Out, line: String) -> Result<()> {
        if w.live {
            self.clear();
        }
        Ok(writeln!(w, "{line}")?)
    }

    /// The progress line again, below what `say` printed.
    fn show(&self, w: &mut Out, t: &Tally, end: bool) -> Result<()> {
        if !w.live && end {
            self.clear();
            std::io::stdout().write_all(&std::mem::take(&mut w.buf))?;
        }
        if w.live || end {
            self.bar(t);
        }
        Ok(())
    }

    /// A row as its run ends (an interrupted campaign keeps it), and into
    /// the totals.
    fn record(&self, g: &mut Tally, row: &Row) -> Result<()> {
        writeln!(g.tsv, "{row}")?;
        g.count(row)
    }

    /// A seed's last line, here and in `seeds.tsv`.
    fn verdict(&self, g: &mut Tally, w: &mut Out, tag: &str, seed: u64, v: Verdict, why: &str) -> Result<()> {
        *g.verdicts.entry(v).or_default() += 1;
        self.say(w, format!("{tag}: {v}{why}"))?;
        writeln!(g.seeds, "{seed}\t{v}")?;
        self.show(w, g, true)
    }

    /// Window `k` of `seed`, against its baseline's `end`: the discovery
    /// and, for a Violation no finding matches, its confirmation and
    /// minimization. Its row and its partial order; None: stopped, and the
    /// window leaves no trace.
    #[allow(clippy::too_many_arguments)]
    fn window(&self, seed: u64, k: usize, target: Option<&EventId>, end: Option<ExitStatus>, rd: &Path, tag: &str, log: &mut Vec<Decision>, w: &mut Out) -> Result<Option<(Row, Option<u64>)>> {
        let (c, r) = (self.c, self.r);
        let t = Instant::now();
        let (out, file) = (rd.join(format!("{k}.log")), rd.join(format!("{k}.sched")));
        let ran = r.discover(seed, target, end, &out, log);
        let unmutated = ran.is_ok() && target.is_some() && !log.iter().any(|d| d.mutation.is_some());
        let mut row = Row { seed, window: Some(k), class: Class::Invalid, status: Status::None, finding: None, decisions: log.len(), partial: partial(log), secs: t.elapsed().as_secs_f64(), note: String::new() };
        let mut canon = None;
        match ran {
            Ok(None) => return Ok(None),
            Err(e) => {
                fs::write(&file, r.schedule(seed, Class::Invalid, false, BTreeSet::new(), log).to_string())?;
                row.note = format!("{e:#}");
            }
            Ok(Some((class, run, s))) => {
                row.class = class;
                // A Violation's canary, kept by discover: removed if the stop discards the window.
                let kept = run.canary.dir.clone();
                drop(run);
                // Before confirm reuses `log`.
                canon = Some(order(log));
                if class == Class::Violation {
                    let mut found = self.found.lock().unwrap();
                    if let Some(i) = found.iter().position(|(d, _)| d.repeated_by(&s.findings, &s.steps)) {
                        found[i].1.push(format!("{seed}:{k}"));
                        (row.status, row.finding) = (Status::Repeat, Some(i + 1));
                    } else {
                        self.say(w, format!("{tag} window {k}: Violation, confirming"))?;
                        match r.confirm(&s, end, Some(&out), log, "  ", w) {
                            Ok(Confirmed::Stopped) => {
                                let _ = fs::remove_dir_all(&kept);
                                return Ok(None);
                            }
                            Err(e) => (row.status, row.note) = (Status::Invalid, format!("{e:#}")),
                            Ok(Confirmed::No) => row.status = Status::Unconfirmed,
                            Ok(Confirmed::Yes(g)) => {
                                let id = g.map(|g| &s.steps[g].id);
                                row.note = match (g, id) {
                                    (Some(g), Some(id)) => format!("guilty step {g} {}", hold(&id.thread, id.nr, &id.path)),
                                    _ => "needs more than one hold".into(),
                                };
                                found.push((Dedup { guilty: id.map(|id| (id.thread.clone(), id.nr, id.path.clone())), findings: s.findings.clone() }, vec![format!("{seed}:{k}")]));
                                let f = c.dir.join(format!("findings/{}", found.len()));
                                fs::create_dir_all(&f)?;
                                fs::write(f.join("schedule"), s.to_string())?;
                                // For --resume: the guilty step's index, or `-`.
                                fs::write(f.join("guilty"), g.map_or("-".into(), |g| g.to_string()) + "\n")?;
                                (row.status, row.finding) = (Status::New, Some(found.len()));
                            }
                        }
                    }
                    if let Some(i) = row.finding {
                        let list: String = found[i - 1].1.iter().map(|s| format!("{s}\n")).collect();
                        fs::write(c.dir.join(format!("findings/{i}/seeds")), list)?;
                    }
                }
                fs::write(&file, s.to_string())?;
            }
        }
        let note = match (unmutated, row.note.is_empty()) {
            (false, _) => row.note,
            (true, true) => "unmutated".into(),
            (true, false) => format!("unmutated; {}", row.note),
        };
        row.note = note.replace(['\t', '\n'], " ");
        Ok(Some((row, canon)))
    }

    /// Worker `wk`: seeds from `next` until they run out or a run is stopped.
    fn worker(&self, wk: usize) -> Result<()> {
        let (c, r) = (self.c, self.r);
        r.isolate(wk)?;
        let mut log = Vec::new();
        let mut w = Out { live: self.jobs == 1, buf: Vec::new() };
        // The `[i/N]` of each line; `[i]` open-ended.
        let of = c.seeds.map_or(String::new(), |n| format!("/{n}"));
        'seeds: loop {
            let idx = self.next.fetch_add(1, Relaxed);
            if c.seeds.is_some_and(|n| idx >= n) {
                break;
            }
            let seed = c.first + idx;
            if self.complete.contains_key(&seed) {
                continue;
            }
            let tag = format!("[{}{of}] seed {seed}", idx + 1);
            let t = Instant::now();
            let rd = c.dir.join(format!("runs/{seed}"));
            fs::create_dir_all(&rd)?;
            let b = match r.baseline(seed, Some(&rd.join("baseline.log")), &mut log) {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(e) => {
                    let note = format!("baseline: {e:#}").replace(['\t', '\n'], " ");
                    let row = Row { seed, window: None, class: Class::Invalid, status: Status::None, finding: None, decisions: log.len(), partial: partial(&log), secs: t.elapsed().as_secs_f64(), note };
                    let mut g = self.tally.lock().unwrap();
                    g.planned = true;
                    self.record(&mut g, &row)?;
                    self.verdict(&mut g, &mut w, &tag, seed, Verdict::Incomplete, &format!(", {}", row.note))?;
                    continue;
                }
            };
            let ws = r.windows(&b.targets);
            let mut g = self.tally.lock().unwrap();
            // The plan, sized by the first baseline to end: a discovery costs
            // about one baseline, plus a confirm and minimization per new
            // Violation, the seeds `jobs` at a time.
            if !std::mem::replace(&mut g.planned, true) {
                let per = ws.len() as u64 + 1;
                self.clear();
                match c.seeds {
                    Some(n) => println!("plan: {n} seeds, {} windows in seed {seed}, ~{} runs, est. {} (+ confirms)", ws.len(), n.saturating_mul(per), hms(n as f64 * per as f64 * b.secs / self.jobs as f64)),
                    None => println!("plan: open-ended, {} windows in seed {seed}, ~{per} runs a seed, est. {} a seed (+ confirms)", ws.len(), hms(per as f64 * b.secs)),
                }
            }
            self.say(&mut w, format!("{tag}: {}", run::telemetry(&log, b.targets.len(), b.secs)))?;
            self.show(&mut w, &g, false)?;
            drop(g);
            // bad: a window's Violation; gap: a window invalid or unmutated.
            let (mut bad, mut gap) = (false, false);
            for (k, target) in &ws {
                let Some((row, canon)) = self.window(seed, *k, target.as_ref(), b.end, &rd, &tag, &mut log, &mut w)? else { break 'seeds };
                let unmutated = row.note.starts_with("unmutated");
                bad |= row.class == Class::Violation;
                gap |= unmutated || row.class == Class::Invalid;
                let mut g = self.tally.lock().unwrap();
                g.orders.extend(canon);
                self.record(&mut g, &row)?;
                let f = row.finding.map_or("-".into(), |i| i.to_string());
                let what = match row.status {
                    Status::New => format!("Violation → confirmed, {} → finding #{f} (new)", row.note),
                    Status::Repeat => format!("Violation → repeat of finding #{f}"),
                    Status::Unconfirmed => "Violation → not confirmed".into(),
                    Status::Invalid => format!("Violation → invalid: {}", row.note),
                    Status::None if row.class == Class::Invalid => format!("invalid: {}", row.note),
                    Status::None => row.class.to_string(),
                };
                self.say(&mut w, format!("{tag} window {k}/{}: {what}{}  {:.1}s", ws.len(), if unmutated { " (unmutated)" } else { "" }, row.secs))?;
                self.show(&mut w, &g, false)?;
            }
            let v = if bad {
                Verdict::Unsafe
            } else if ws[0].0 == 0 {
                Verdict::NoWindows
            } else if gap {
                Verdict::Incomplete
            } else {
                Verdict::Safe
            };
            self.verdict(&mut self.tally.lock().unwrap(), &mut w, &tag, seed, v, "")?;
        }
        // An interrupted seed's lines so far.
        if !w.buf.is_empty() {
            self.show(&mut w, &self.tally.lock().unwrap(), true)?;
        }
        Ok(())
    }
}

/// `run`: sweep the campaign's seeds, each exhaustive over its windows. The
/// exit status: 0, 3 with a confirmed finding, 130 interrupted, 1 if the
/// gate scheduler was lost.
pub fn run(c: Campaign) -> Result<i32> {
    let dir = &c.dir;
    // An old campaign's runs/ and findings/ read as this one's: only if it is this one.
    if c.resume {
        let old: Config = fs::read_to_string(dir.join("config")).with_context(|| format!("--resume: {} holds no campaign", dir.display()))?.parse().with_context(|| dir.join("config").display().to_string())?;
        ensure!(old == c.cfg, "--resume: the campaign differs from {} (only --seeds, --first-seed, --time, --jobs and -v may)", dir.join("config").display());
    } else {
        ensure!(fs::read_dir(dir).map_or(true, |mut e| e.next().is_none()), "run: {} is not empty (--resume continues its campaign)", dir.display());
    }
    run::check_private(&c.cfg, Some(dir))?;
    if let Ok(cpus) = std::thread::available_parallelism() {
        if c.jobs > cpus.get() {
            eprintln!("warning: --jobs {} > {cpus} CPUs: runs compete for them, and more decisions turn partial", c.jobs);
        }
    }
    let r = Runner::new(c.cfg.clone(), c.verbose, c.time)?;
    println!("{}", r.alice);
    fs::create_dir_all(dir.join("runs")).with_context(|| dir.display().to_string())?;
    fs::write(dir.join("config"), c.cfg.to_string())?;
    let sweep = Sweep::open(&c, &r)?;
    let sweep = &sweep;
    std::thread::scope(|s| {
        let ws: Vec<_> = (0..sweep.jobs)
            .map(|wk| {
                s.spawn(move || {
                    // An error or a panic stops the other workers alike.
                    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sweep.worker(wk)));
                    if !matches!(done, Ok(Ok(()))) {
                        sweep.r.fatal.store(true, Relaxed);
                    }
                    done.unwrap_or_else(|p| std::panic::resume_unwind(p))
                })
            })
            .collect();
        ws.into_iter().map(|h| h.join().expect("worker panicked")).collect::<Result<Vec<()>>>()
    })?;
    sweep.clear();
    let t = sweep.tally.lock().unwrap();
    let found = sweep.found.lock().unwrap();

    let (stopped, lost, done) = (engine::stopped(), r.lost.load(Relaxed), t.done());
    if stopped {
        println!("interrupted: {done} seeds complete");
    } else if lost {
        println!("scheduler lost: {done} seeds complete");
    } else if c.seeds.is_none_or(|n| done < n) {
        // Only a stop, a lost scheduler or --time ends the loop early.
        println!("time limit: {done} seeds complete");
    }
    println!("campaign: {} seeds, {} runs, {} invalid, discovery {:.1}s", c.seeds.unwrap_or(done), t.total, t.invalid, t.time.as_secs_f64());
    let v: Vec<String> = VERDICTS.iter().map(|v| format!("{} {v}", t.verdicts.get(v).copied().unwrap_or(0))).collect();
    println!("seeds: {}", v.join(", "));
    println!("distinct partial orders: {}{}", t.orders.len(), if sweep.complete.is_empty() { "" } else { " (this session's runs only)" });
    println!("partial decisions: {}/{} ({:.0}%)", t.partial, t.decisions, 100.0 * t.partial as f64 / t.decisions.max(1) as f64);
    if t.unmutated > 0 {
        println!("unmutated: {}/{} runs never reached their target", t.unmutated, t.total);
    }
    println!("findings: {}", found.len());
    for (i, (d, runs)) in found.iter().enumerate() {
        let guilty = d.guilty.as_ref().map_or("needs more than one hold".into(), |(t, nr, p)| hold(t, *nr, p));
        println!("finding #{}: {} runs, guilty {guilty}, {:?}, {}", i + 1, runs.len(), d.findings, dir.join(format!("findings/{}", i + 1)).display());
    }
    Ok(if stopped { 130 } else if lost { 1 } else if found.is_empty() { 0 } else { 3 })
}
