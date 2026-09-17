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

/// What a run produced, independent of which backend produced it.
struct RunReport {
    outcome: RunOutcome,
    canonical: CanonicalLog,
    debug: DebugLog,
    /// Backend-specific diagnostics, if any.
    notes: Option<String>,
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

    let backend = SeccompNotifyBackend::new(specs, args.cgroup_path.clone())
        .with_poll_timeout(Duration::from_millis(args.poll_timeout_ms));

    let mut engine = Engine::new(config, backend);
    let outcome = engine.run()?;
    let b = engine.backend();
    // Printed rather than only counted: section 14-A is a question about this
    // exact sequence, and the only way to answer it is to compare it across
    // runs.
    let notes = format!("arrival: {}", b.arrival_trace().join(" "));
    let notes = format!(
        "{notes}\nready-sets: {}",
        engine.decision_trace().join(" | ")
    );
    Ok(RunReport {
        outcome,
        canonical: engine.canonical_log().clone(),
        debug: engine.debug_log().clone(),
        notes: Some(notes),
    })
}
