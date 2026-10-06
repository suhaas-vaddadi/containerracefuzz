// SPDX-License-Identifier: GPL-2.0
//
// CLI entry point.
//
// There is no `--replay` / `--discover` flag: the mode is a property of the
// config, which carries either `steps[]` or a `policy` block and never both
// (design doc section 8). That is section 3.1's argument made operational --
// one engine, one log format, used two ways.
//
// Which *processes* to launch is not in that schema, and deliberately stays
// out of it: launching the scenario is the harness's job (Background, "Blast
// radius and harness"), and section 6.1 makes the same separation for the
// mutator. `--spawn` is a placeholder for the harness, not a schema addition.

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use scx_crfuzz::config::Mode;
use scx_crfuzz::log::CanonicalLog;
use scx_crfuzz::log::DebugLog;
use scx_crfuzz::oracle::OracleVerdict;
use scx_crfuzz::RunOutcome;
use scx_crfuzz::ScenarioConfig;
use simplelog::ColorChoice;
use simplelog::LevelFilter;
use simplelog::TermLogger;
use simplelog::TerminalMode;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "scx_crfuzz",
    about = "ContainerRaceFuzz: deterministic replay and race discovery for container runtime TOCTOU bugs"
)]
struct Args {
    /// Scenario config (JSON). Replay mode if it carries `steps`, discovery
    /// mode if it carries `policy`.
    #[arg(short, long)]
    config: PathBuf,

    /// A process to launch and instrument, as a whitespace-separated command
    /// line. Repeat for each. Linux only.
    #[arg(long = "spawn", required = true)]
    spawn: Vec<String>,

    /// An OCI bundle to check before running: if its `linux.seccomp` profile
    /// denies a syscall a checkpoint sits on, refuse to start.
    ///
    /// Seccomp filters stack and the kernel takes the most restrictive action,
    /// and `USER_NOTIF` -- the whole holding mechanism -- loses to `ERRNO`. A
    /// profile that denies a checkpoint's syscall therefore erases that
    /// checkpoint silently: no error, no failed release, the notification
    /// simply never arrives. Refusing up front turns a timeout that looks like
    /// an engine bug, or a discovery run that quietly explores less than it
    /// claims, into a config error that says what is wrong.
    #[arg(long, value_name = "DIR")]
    oci_bundle: Option<PathBuf>,

    /// Exit with the status of the `--spawn` at INDEX (0 if given bare)
    /// instead of the engine's verdict.
    ///
    /// For standing in for the binary being instrumented. `ctr run
    /// --runc-binary <wrapper>` makes containerd's shim exec the wrapper where
    /// it would have exec'd `runc`, and the shim reads the exit status to
    /// decide whether the container was created -- so reporting "the scheduling
    /// run completed" there would tell it a container exists when it does not.
    /// The index is what lets a wrapper carry the instrumented binary *and*
    /// other processes (racers, attackers). The engine's own outcome still
    /// goes to the log, and to `--out` if given. Requires `--out`: the shim
    /// never drains stdout.
    #[arg(long, value_name = "INDEX", num_args = 0..=1, default_missing_value = "0", requires = "out")]
    exit_with_spawn: Option<usize>,

    /// Write the canonical log (`log`), projected replay schedule
    /// (`schedule.json`, design doc section 3.5) and debug log (`debug`, pids
    /// and timings, never byte-compared) into this directory. Without it the
    /// canonical log goes to stdout and nothing else is written.
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,
}

/// Whether the container's own seccomp profile would erase our checkpoints.
///
/// Binary-only, deliberately: the crate docs put OCI strictly upstream of the
/// engine, so this sits with `--spawn` as harness work rather than inside the
/// library.
#[cfg(target_os = "linux")]
mod oci_preflight;

/// What a run produced, independent of which backend produced it.
struct RunReport {
    outcome: RunOutcome,
    canonical: CanonicalLog,
    debug: DebugLog,
    /// Oracle rulings, one per observed window. Empty unless `auto_attack`.
    verdicts: Vec<(u64, OracleVerdict)>,
    /// Bounded backend diagnostics (counts): safe to write to any
    /// stream, including one that may never be drained.
    notes: Option<String>,
    /// Unbounded per-event traces (`ready-sets:`): written to the
    /// debug-log file, never to a stream. As one line these can exceed a pipe
    /// buffer and block the process forever when the reader is a containerd
    /// shim holding container stdio, so they must not go to stderr.
    traces: Option<String>,
    /// The spawned process's own exit status, for `--exit-with-spawn`. `None`
    /// when there was no real process, or it was never reaped.
    child_exit: Option<i32>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    TermLogger::init(
        if args.verbose {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        },
        simplelog::Config::default(),
        // Stderr, not Mixed: stdout carries the canonical log, and a run
        // redirected to a file must produce a log that can be byte-compared,
        // not one with log lines interleaved into it.
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;

    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let config = ScenarioConfig::from_json(&text)
        .with_context(|| format!("parsing {}", args.config.display()))?;

    log::info!(
        "scenario `{}`: {} role(s), {} checkpoint(s), mode {}",
        config.scenario_id,
        config.roles.len(),
        config.checkpoints.len(),
        match &config.mode {
            Mode::Replay { steps } => format!("replay ({} steps)", steps.len()),
            Mode::Discovery { policy } => format!("discovery ({:?})", policy.policy_type),
        }
    );

    let report = run(config, &args)?;

    log::info!(
        "outcome: {:?} after {} decision(s)",
        report.outcome,
        report.canonical.len()
    );
    if let Some(notes) = &report.notes {
        log::info!("{notes}");
    }

    // Findings are the point of a discovery run: print each one plainly and
    // summarise, so a run that found something is obvious in the log rather
    // than buried in a warn line.
    let findings: Vec<(u64, &str)> = report
        .verdicts
        .iter()
        .filter_map(|(step, v)| match v {
            OracleVerdict::Violation(reason) => Some((*step, reason.as_str())),
            OracleVerdict::Clean => None,
        })
        .collect();
    if !report.verdicts.is_empty() {
        log::info!(
            "oracle: {} window(s) observed, {} finding(s)",
            report.verdicts.len(),
            findings.len()
        );
    }
    for (step, reason) in &findings {
        log::error!("FINDING at step {step}: {reason}");
    }

    if let Some(dir) = &args.out {
        if let Err(e) = write_out(dir, &report) {
            if args.exit_with_spawn.is_none() {
                return Err(e);
            }
            // Standing in for the child: its status matters more than ours.
            log::error!("writing --out: {e:#}");
        }
    } else {
        print!("{}", report.canonical.render());
    }

    // A run that did not complete is a failed run, and the exit status should
    // say so: these are driven from shell loops that need to tell the cases
    // apart without parsing the log.
    if args.exit_with_spawn.is_some() {
        // Deliberately unconditional on the outcome: the caller asked to stand
        // in for the child, and a wrapper that substitutes its own verdict on a
        // timeout is exactly the failure this flag exists to avoid. The outcome
        // was logged above either way.
        match report.child_exit {
            Some(code) => std::process::exit(code),
            None => {
                log::error!(
                    "--exit-with-spawn, but the spawned process was never reaped; \
                     reporting 2 rather than inventing a status for it"
                );
                std::process::exit(2);
            }
        }
    }

    match report.outcome {
        RunOutcome::Completed => Ok(()),
        other => {
            log::error!("run did not complete: {other:?}");
            std::process::exit(2);
        }
    }
}

fn write_out(dir: &std::path::Path, report: &RunReport) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(dir.join("log"), report.canonical.render())?;
    std::fs::write(
        dir.join("schedule.json"),
        serde_json::to_string_pretty(&report.canonical.project_to_steps())?,
    )?;

    // The debug log is the one non-compared output file, so the unbounded
    // ready-set traces belong here and not on stderr.
    let mut rendered = report.debug.render();
    if let Some(traces) = &report.traces {
        rendered
            .push_str("\n# ready-set traces (section 14-A; never byte-compared)\n");
        rendered.push_str(traces);
        rendered.push('\n');
    }
    std::fs::write(dir.join("debug"), rendered)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run(_config: ScenarioConfig, _args: &Args) -> Result<RunReport> {
    anyhow::bail!("holding a process needs Linux; the library and its tests run anywhere")
}

/// Set by SIGINT/SIGTERM; the engine checks it once per round.
#[cfg(target_os = "linux")]
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Removes this run's cgroup on the way out, on every path. When the run did
/// not complete, whatever is still inside is killed first: an abandoned victim
/// would otherwise keep the directory busy forever.
#[cfg(target_os = "linux")]
struct CgroupGuard {
    dir: PathBuf,
    kill: bool,
}

#[cfg(target_os = "linux")]
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if self.kill {
            // cgroup.kill (Linux 5.14) SIGKILLs every task in the cgroup.
            if let Err(e) = std::fs::write(self.dir.join("cgroup.kill"), "1") {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("killing {}: {e}", self.dir.display());
                }
            }
        }
        // Killed tasks leave asynchronously; give them a moment.
        for _ in 0..50 {
            match std::fs::remove_dir(&self.dir) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(e) => {
                    log::warn!("removing cgroup {}: {e}", self.dir.display());
                    return;
                }
            }
        }
        log::warn!("cgroup {} still has tasks; leaving it", self.dir.display());
    }
}

/// Spawn the scenario under the `sched_ext` gate and drive the engine.
///
/// The gate is always used: it carries the thread-state sensor, and holds the
/// victim's thread group during an `auto_attack` window. Without
/// `scx_crfuzz_gated` attached, `GateBackend` refuses to start.
#[cfg(target_os = "linux")]
fn run(config: ScenarioConfig, args: &Args) -> Result<RunReport> {
    use scx_crfuzz::backend_gate::GateBackend;
    use scx_crfuzz::backend_seccomp::ProcessSpec;
    use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;

    if let Some(bundle) = &args.oci_bundle {
        preflight_bundle(bundle, &config)?;
    }

    if let Some(i) = args.exit_with_spawn {
        if i >= args.spawn.len() {
            anyhow::bail!(
                "--exit-with-spawn {i} is out of range: only {} --spawn(s) were given",
                args.spawn.len()
            );
        }
    }

    // One cgroup per invocation, so concurrent runs -- one runc wrapper per
    // container under containerd -- never share one.
    let cgroup = format!(
        "{}/{}",
        config.cgroup.trim_end_matches('/'),
        std::process::id()
    );

    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    let action = SigAction::new(SigHandler::Handler(on_stop_signal), SaFlags::empty(), SigSet::empty());
    for sig in [Signal::SIGINT, Signal::SIGTERM] {
        // SAFETY: the handler only stores to an atomic. Handlers reset to the
        // default across exec, so spawned processes are unaffected.
        unsafe { sigaction(sig, &action) }.context("installing a stop handler")?;
    }

    let mut cgroup_guard = CgroupGuard { // `mut`: `kill` is set after the run
        dir: std::path::Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
        kill: true,
    };

    let specs = args
        .spawn
        .iter()
        .map(|s| ProcessSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;

    let seccomp = SeccompNotifyBackend::new(specs, cgroup.clone()).with_sched_ext(true);
    let backend = GateBackend::new(seccomp)?;
    let mut engine = scx_crfuzz::Engine::new(config, backend).with_stop(&STOP);
    let outcome = engine.run();

    // A completed `runc create` may leave the container's tasks in flight
    // to their own cgroup; never kill on success.
    cgroup_guard.kill = !matches!(outcome, Ok(RunOutcome::Completed));
    let outcome = outcome?;

    // Bounded: this is what reaches stderr, and it is safe on a stream that is
    // never drained.
    let notes = format!(
        "ready-sets: {} decision(s); {} during a timed sleep, {} while a thread was frozen \
         (non-zero: not seed-reproducible)",
        engine.decision_trace().len(),
        engine.timed_sleep_decisions(),
        engine.frozen_decisions()
    );
    // Unbounded: section 14-A is a question about this exact sequence, and the
    // only way to answer it is to compare it across runs -- so it is kept in
    // full, but in a file, where its size cannot block the run.
    let traces = format!("ready-sets: {}", engine.decision_trace().join(" | "));

    Ok(RunReport {
        outcome,
        canonical: engine.canonical_log().clone(),
        debug: engine.debug_log().clone(),
        verdicts: engine.oracle_verdicts().to_vec(),
        notes: Some(notes),
        traces: Some(traces),
        child_exit: args
            .exit_with_spawn
            .and_then(|i| engine.backend().inner().child_exit_code_at(i)),
    })
}

/// Refuse to run a scenario whose checkpoints the bundle's profile would erase.
#[cfg(target_os = "linux")]
fn preflight_bundle(bundle: &std::path::Path, config: &ScenarioConfig) -> Result<()> {
    let path = bundle.join("config.json");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let report = oci_preflight::check(&text, &config.checkpoints)?;

    if !report.profile_present {
        log::info!(
            "{} has no linux.seccomp block, so nothing can mask a checkpoint",
            path.display()
        );
        return Ok(());
    }
    for name in &report.absent_on_this_arch {
        log::warn!(
            "checkpoint on `{name}`: this architecture has no such syscall, so it can \
             never fire -- not the profile's doing"
        );
    }
    for c in &report.conditional {
        log::warn!(
            "checkpoint `{}` ({}) may not fire: profile says {}{}",
            c.checkpoint,
            c.syscall,
            c.action,
            c.caveat
                .as_deref()
                .map(|w| format!(" -- {w}"))
                .unwrap_or_default()
        );
    }
    if !report.masked.is_empty() {
        let lines = report
            .masked
            .iter()
            .map(|m| format!("  `{}` ({}) -> {}", m.checkpoint, m.syscall, m.action))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "the bundle's seccomp profile erases {n} of this scenario's checkpoint(s):\n\
             {lines}\n\
             Seccomp filters stack and the kernel takes the most restrictive action, so \
             a denied syscall never reaches our listener: the checkpoint would silently \
             never fire. Allow these in the profile, or drop them from the scenario.",
            n = report.masked.len(),
        );
    }
    log::info!(
        "bundle profile checked: none of the {} checkpoint(s) are masked",
        config.checkpoints.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_with_spawn_requires_out() {
        let r = Args::try_parse_from(["scx_crfuzz", "-c", "x.json", "--spawn", "true", "--exit-with-spawn"]);
        assert!(r.is_err(), "a shim-facing run must not print the log to an undrained stdout");
        let ok = Args::try_parse_from([
            "scx_crfuzz", "-c", "x.json", "--spawn", "true", "--exit-with-spawn", "--out", "/tmp/o",
        ]);
        assert!(ok.is_ok());
    }
}
