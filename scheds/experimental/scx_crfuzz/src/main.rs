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
use scx_crfuzz::backend::StubBackend;
use scx_crfuzz::config::Mode;
use scx_crfuzz::log::CanonicalLog;
use scx_crfuzz::log::DebugLog;
use scx_crfuzz::Engine;
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
    /// line. Repeat for each. Linux only; without any, the engine runs against
    /// the scripted stub backend and holds nothing.
    #[arg(long = "spawn")]
    spawn: Vec<String>,

    /// cgroup v2 path to place spawned processes in, spelled as it appears in
    /// `/proc/<pid>/cgroup` -- e.g. `/crfuzz/run0`, not
    /// `/sys/fs/cgroup/crfuzz/run0`. Must sit under the config's `cgroup`.
    #[arg(long, default_value = "/crfuzz/run0")]
    cgroup_path: String,

    /// Wrap the seccomp backend in the cgroup freezer, so holding a role holds
    /// every OS thread in it rather than only the one that made the syscall.
    ///
    /// Required for any multi-threaded target -- a Go binary such as `runc`
    /// keeps running on its other threads while one sits in a notification.
    /// Also switches each `--spawn` into its own `<cgroup-path>/spawn<i>`, since
    /// roles sharing one cgroup would share a freezer and deadlock each other.
    ///
    /// This is a proof of concept and it perturbs what it measures: freezing
    /// restarts the held syscall. See the crate README's `ops.dispatch` TODO.
    #[arg(long)]
    freezer: bool,

    /// Hold thread groups with the `sched_ext` gate instead of the cgroup
    /// freezer. Requires `scx_crfuzz_gated` to be running.
    ///
    /// This is the intended mechanism: unlike `--freezer` it does not restart
    /// the syscall it holds. Mutually exclusive with `--freezer`.
    #[arg(long, conflicts_with = "freezer")]
    gate: bool,

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

    /// Exit with the spawned process's status instead of the engine's verdict.
    ///
    /// For standing in for the binary being instrumented. `ctr run
    /// --runc-binary <wrapper>` makes containerd's shim exec the wrapper where
    /// it would have exec'd `runc`, and the shim reads the exit status to
    /// decide whether the container was created -- so reporting "the scheduling
    /// run completed" there would tell it a container exists when it does not.
    ///
    /// Requires exactly one `--spawn`: with several there is no single status
    /// to report. The engine's own outcome still goes to the log, and to
    /// `--canonical-log` / `--project-schedule` if asked for.
    #[arg(long)]
    exit_with_child: bool,

    /// How long each backend poll waits for a notification.
    #[arg(long, default_value_t = 50)]
    poll_timeout_ms: u64,

    /// Write the canonical log here instead of stdout.
    #[arg(long)]
    canonical_log: Option<PathBuf>,

    /// Write the projected replay schedule (design doc section 3.5) here.
    #[arg(long)]
    project_schedule: Option<PathBuf>,

    /// Write the debug log (pids, timings) here. Never byte-compared.
    #[arg(long)]
    debug_log: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,
}

/// Whether the container's own seccomp profile would erase our checkpoints.
///
/// Binary-only, deliberately: the crate docs put OCI strictly upstream of the
/// engine, so this sits with `--spawn` and `--cgroup-path` as harness work
/// rather than inside the library.
#[cfg(target_os = "linux")]
mod oci_preflight;

/// What a run produced, independent of which backend produced it.
struct RunReport {
    outcome: RunOutcome,
    canonical: CanonicalLog,
    debug: DebugLog,
    /// Backend-specific diagnostics, if any.
    notes: Option<String>,
    /// The spawned process's own exit status, for `--exit-with-child`. `None`
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

    match &args.canonical_log {
        Some(p) => std::fs::write(p, report.canonical.render())?,
        None => print!("{}", report.canonical.render()),
    }
    if let Some(p) = &args.project_schedule {
        std::fs::write(
            p,
            serde_json::to_string_pretty(&report.canonical.project_to_steps())?,
        )?;
    }
    if let Some(p) = &args.debug_log {
        std::fs::write(p, report.debug.render())?;
    }

    // A run that did not complete is a failed run, and the exit status should
    // say so: these are driven from shell loops that need to tell the cases
    // apart without parsing the log.
    if args.exit_with_child {
        // Deliberately unconditional on the outcome: the caller asked to stand
        // in for the child, and a wrapper that substitutes its own verdict on a
        // timeout is exactly the failure this flag exists to avoid. The outcome
        // was logged above either way.
        match report.child_exit {
            Some(code) => std::process::exit(code),
            None => {
                log::error!(
                    "--exit-with-child, but the spawned process was never reaped; \
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

fn run_stub(config: ScenarioConfig, note: Option<String>) -> Result<RunReport> {
    let mut engine = Engine::new(config, StubBackend::new());
    let outcome = engine.run()?;
    Ok(RunReport {
        outcome,
        canonical: engine.canonical_log().clone(),
        debug: engine.debug_log().clone(),
        notes: note,
        child_exit: None,
    })
}

#[cfg(not(target_os = "linux"))]
fn run(config: ScenarioConfig, _args: &Args) -> Result<RunReport> {
    run_stub(
        config,
        Some(
            "this is not Linux: no process can be held here, so the engine ran against \
             the scripted stub backend"
                .to_string(),
        ),
    )
}

#[cfg(target_os = "linux")]
fn run(config: ScenarioConfig, args: &Args) -> Result<RunReport> {
    use scx_crfuzz::backend_seccomp::ProcessSpec;
    use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
    use std::time::Duration;

    if args.spawn.is_empty() {
        return run_stub(
            config,
            Some(
                "no --spawn given, so the engine ran against the scripted stub backend and \
                 held nothing"
                    .to_string(),
            ),
        );
    }

    if let Some(bundle) = &args.oci_bundle {
        preflight_bundle(bundle, &config)?;
    }

    if args.exit_with_child && args.spawn.len() != 1 {
        anyhow::bail!(
            "--exit-with-child needs exactly one --spawn to answer for, got {}",
            args.spawn.len()
        );
    }

    if !args.cgroup_path.starts_with(&config.cgroup) {
        anyhow::bail!(
            "--cgroup-path `{}` is not inside the config's cgroup `{}`, so no spawned \
             process could ever match a role",
            args.cgroup_path,
            config.cgroup
        );
    }

    let specs = args
        .spawn
        .iter()
        .map(|s| ProcessSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;

    let seccomp = SeccompNotifyBackend::new(specs, args.cgroup_path.clone())
        .with_poll_timeout(Duration::from_millis(args.poll_timeout_ms));

    if args.gate {
        use scx_crfuzz::backend_gate::GateBackend;
        // No per-spawn cgroups: unlike the freezer, the gate acts on the
        // thread group the held task belongs to, so roles sharing one cgroup
        // do not interfere.
        let backend = GateBackend::new(seccomp.with_sched_ext(true))?;
        return run_engine(
            config,
            backend,
            |b| {
                let s = b.stats();
                format!(
                    "{}\ngate: {} gate(s), {} ungate(s), max gate latency {:?} \
                     (the cost to issue the hold: notification to kick-complete, \
                     not the residual window before it takes effect)",
                    b.inner().arrival_trace().join(" "),
                    s.gates,
                    s.ungates,
                    s.max_gate_latency
                )
            },
            |b| b.inner().child_exit_code(),
        );
    }

    if args.freezer {
        use scx_crfuzz::backend_freezer::FreezerBackend;
        // Per-spawn cgroups are not optional here: the freezer acts on whatever
        // cgroup the held task is in, so with one shared cgroup the first role
        // to reach a checkpoint freezes every other role and the second never
        // arrives at all.
        let backend = FreezerBackend::new(seccomp.with_per_spawn_cgroups(true));
        run_engine(
            config,
            backend,
            |b| {
                let s = b.stats();
                format!(
                    "{}\nfreezer: {} freeze(s), {} thaw(s), max freeze latency {:?} \
                 (the window in which siblings were still running)",
                    b.inner().arrival_trace().join(" "),
                    s.freezes,
                    s.thaws,
                    s.max_freeze_latency
                )
            },
            |b| b.inner().child_exit_code(),
        )
    } else {
        run_engine(
            config,
            seccomp,
            |b| b.arrival_trace().join(" "),
            |b| b.child_exit_code(),
        )
    }
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

/// Drive an engine to completion and package what it produced.
///
/// Generic over the backend so the freezer-wrapped and bare cases share one
/// path; `arrival` is the only thing that differs, since reaching the section
/// 14-A arrival trace means going through the wrapper when there is one.
#[cfg(target_os = "linux")]
fn run_engine<B: scx_crfuzz::backend::CheckpointBackend>(
    config: ScenarioConfig,
    backend: B,
    arrival: impl FnOnce(&B) -> String,
    child_exit: impl FnOnce(&B) -> Option<i32>,
) -> Result<RunReport> {
    let mut engine = Engine::new(config, backend);
    let outcome = engine.run()?;
    // Printed rather than only counted: section 14-A is a question about this
    // exact sequence, and the only way to answer it is to compare it across
    // runs.
    let notes = format!("arrival: {}", arrival(engine.backend()));
    let notes = format!(
        "{notes}\nready-sets: {}",
        engine.decision_trace().join(" | ")
    );
    let child_exit = child_exit(engine.backend());
    Ok(RunReport {
        outcome,
        canonical: engine.canonical_log().clone(),
        debug: engine.debug_log().clone(),
        notes: Some(notes),
        child_exit,
    })
}
