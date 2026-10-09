// SPDX-License-Identifier: GPL-2.0
//
// CLI entry point: one run of the sweep.
//
// Which processes to launch is not in the config: launching the scenario is
// the harness's job (Background, "Blast radius and harness"), so `--spawn`
// carries it.

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use scx_crfuzz::engine::Finding;
use scx_crfuzz::engine::Window;
use scx_crfuzz::RunOutcome;
use scx_crfuzz::ScenarioConfig;
use simplelog::ColorChoice;
use simplelog::LevelFilter;
use simplelog::TermLogger;
use simplelog::TerminalMode;
use std::fmt::Write as _;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "scx_crfuzz",
    about = "ContainerRaceFuzz: sweep attack windows for container runtime TOCTOU bugs"
)]
struct Args {
    /// Scenario config (JSON).
    #[arg(short, long)]
    config: PathBuf,

    /// The window to attack, `<checkpoint>#<n>`; overrides `attack.at`.
    /// Without either, this is a dry run that only lists the windows.
    #[arg(long)]
    at: Option<String>,

    /// A process to launch and instrument, as a whitespace-separated command
    /// line. Repeat for each. Linux only.
    #[arg(long = "spawn", required = true)]
    spawn: Vec<String>,

    /// cgroup v2 path to place spawned processes in, spelled as it appears in
    /// `/proc/<pid>/cgroup` -- e.g. `/crfuzz/run0`, not
    /// `/sys/fs/cgroup/crfuzz/run0`. Must sit under the config's `cgroup`.
    #[arg(long, default_value = "/crfuzz/run0")]
    cgroup_path: String,

    /// Hold the victim's whole thread group with the `sched_ext` gate.
    /// Requires `scx_crfuzz_gated` to be running.
    ///
    /// Without it only the thread at the checkpoint is held, and a Go
    /// victim's other threads keep running through the attacker's window.
    #[arg(long)]
    gate: bool,

    /// An OCI bundle: refuse to start if its `linux.seccomp` profile denies a
    /// syscall a checkpoint sits on, and read the container's cgroup from it
    /// for victim matching.
    ///
    /// Seccomp filters stack and `USER_NOTIF` -- the whole holding mechanism
    /// -- loses to `ERRNO`, so a profile that denies a checkpoint's syscall
    /// erases that checkpoint silently.
    #[arg(long, value_name = "DIR")]
    oci_bundle: Option<PathBuf>,

    /// Exit with the spawned process's status instead of the engine's verdict.
    ///
    /// For standing in for the binary being instrumented: `ctr run
    /// --runc-binary <wrapper>` makes containerd's shim exec the wrapper where
    /// it would have exec'd `runc`, and the shim reads the exit status to
    /// decide whether the container was created. Requires exactly one
    /// `--spawn`.
    #[arg(long)]
    exit_with_child: bool,

    /// How long each backend poll waits for a notification.
    #[arg(long, default_value_t = 50)]
    poll_timeout_ms: u64,

    /// Write the report (windows and findings) here instead of stdout.
    #[arg(long)]
    report: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,
}

/// Whether the container's own seccomp profile would erase our checkpoints,
/// and the container's cgroup. Binary-only, so the library never learns what
/// OCI is.
#[cfg(target_os = "linux")]
mod oci_preflight;

/// What a run produced, independent of which backend produced it.
struct RunReport {
    outcome: RunOutcome,
    windows: Vec<Window>,
    findings: Vec<Finding>,
    attacked: bool,
    notes: Option<String>,
    /// The spawned process's own exit status, for `--exit-with-child`.
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
        // Stderr: stdout carries the report.
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;

    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let mut config = ScenarioConfig::from_json(&text)
        .with_context(|| format!("parsing {}", args.config.display()))?;
    if args.at.is_some() {
        config.attack.at = args.at.clone();
    }
    let at = config.attack.at.clone();
    log::info!(
        "victim `{}`, {} checkpoint(s), {}",
        config.victim.comm,
        config.checkpoints.len(),
        match &at {
            Some(w) => format!("attacking {w}"),
            None => "dry run".to_string(),
        }
    );

    let report = run(config, &args)?;

    log::info!(
        "outcome: {:?}, {} window(s), {} finding(s)",
        report.outcome,
        report.windows.len(),
        report.findings.len()
    );
    if let Some(notes) = &report.notes {
        log::info!("{notes}");
    }
    if let (Some(w), false) = (&at, report.attacked) {
        log::error!("window {w} was never reached: nothing was attacked");
    }
    for f in &report.findings {
        log::error!("FINDING at {}: {}", f.seen_at, f.reason);
    }

    // One line per window, then per finding, then `unreached` if the selected
    // window never came, tab-separated so the sweep can cut it. Paths under the
    // bundle are written relative to it, so a run on a scratch copy compares
    // with another.
    let bundle = args.oci_bundle.as_deref().and_then(|b| std::fs::canonicalize(b).ok());
    let mut out = String::new();
    for w in &report.windows {
        let path = w.path.as_ref().map(|p| {
            match bundle.as_deref().and_then(|b| p.strip_prefix(b).ok()) {
                Some(rel) => format!("<bundle>/{}", rel.display()),
                None => p.display().to_string(),
            }
        });
        let _ = writeln!(out, "window\t{}\t{}", w.key, path.as_deref().unwrap_or("-"));
    }
    for f in &report.findings {
        let _ = writeln!(out, "finding\t{}\t{}", f.seen_at, f.reason);
    }
    if let (Some(w), false) = (&at, report.attacked) {
        let _ = writeln!(out, "unreached\t{w}");
    }
    match &args.report {
        Some(p) => std::fs::write(p, out)?,
        None => print!("{out}"),
    }

    if args.exit_with_child {
        // Unconditional on the outcome: the caller asked to stand in for the
        // child, and substituting the engine's verdict is exactly what this
        // flag exists to avoid. The outcome was logged above.
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

#[cfg(not(target_os = "linux"))]
fn run(_config: ScenarioConfig, _args: &Args) -> Result<RunReport> {
    anyhow::bail!("holding a process needs Linux; the library and its tests run anywhere")
}

#[cfg(target_os = "linux")]
fn run(mut config: ScenarioConfig, args: &Args) -> Result<RunReport> {
    use scx_crfuzz::backend_seccomp::ProcessSpec;
    use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
    use std::time::Duration;

    if let Some(bundle) = &args.oci_bundle {
        let path = bundle.join("config.json");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        preflight_bundle(&path, &text, &config)?;
        if config.container_cgroup.is_none() {
            config.container_cgroup = oci_preflight::container_cgroup(&text)?;
        }
    }

    if args.exit_with_child && args.spawn.len() != 1 {
        anyhow::bail!(
            "--exit-with-child needs exactly one --spawn to answer for, got {}",
            args.spawn.len()
        );
    }

    if !scx_crfuzz::config::under_cgroup(&args.cgroup_path, &config.cgroup) {
        anyhow::bail!(
            "--cgroup-path `{}` is not inside the config's cgroup `{}`, so no spawned \
             process could ever be the victim",
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
        let backend = GateBackend::new(seccomp.with_sched_ext(true))?;
        return run_engine(
            config,
            backend,
            |b| {
                let s = b.stats();
                Some(format!(
                    "gate: {} gate(s), {} ungate(s), max gate latency {:?} \
                     (the cost to issue the hold: notification to kick-complete, \
                     not the residual window before it takes effect)",
                    s.gates, s.ungates, s.max_gate_latency
                ))
            },
            |b| b.inner().child_exit_code(),
        );
    }

    run_engine(config, seccomp, |_| None, |b| b.child_exit_code())
}

/// Refuse to run a scenario whose checkpoints the bundle's profile would erase.
#[cfg(target_os = "linux")]
fn preflight_bundle(path: &std::path::Path, text: &str, config: &ScenarioConfig) -> Result<()> {
    let report = oci_preflight::check(text, &config.checkpoints)?;

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
#[cfg(target_os = "linux")]
fn run_engine<B: scx_crfuzz::backend::CheckpointBackend>(
    config: ScenarioConfig,
    backend: B,
    notes: impl FnOnce(&B) -> Option<String>,
    child_exit: impl FnOnce(&B) -> Option<i32>,
) -> Result<RunReport> {
    let mut engine = scx_crfuzz::Engine::new(config, backend);
    let outcome = engine.run()?;
    Ok(RunReport {
        outcome,
        windows: engine.windows().to_vec(),
        findings: engine.findings().to_vec(),
        attacked: engine.attacked(),
        notes: notes(engine.backend()),
        child_exit: child_exit(engine.backend()),
    })
}
