// SPDX-License-Identifier: GPL-2.0
//
// CLI entry point. See
// docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md.

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use scx_crfuzz::config::ScenarioConfig;
use scx_crfuzz_gen::derive::build_config;
use scx_crfuzz_gen::derive::RoleTrace;
use scx_crfuzz_gen::tracer::derive_comm;
use scx_crfuzz_gen::tracer::ProcessTracer;
use scx_crfuzz_gen::tracer::StraceTracer;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "crfuzz_gen",
    about = "Generate a discovery-mode scx_crfuzz scenario config from real traced behavior"
)]
struct Args {
    #[arg(long)]
    scenario_id: String,

    #[arg(long)]
    cgroup: String,

    /// `name:command line`, repeatable -- one per role. At least two are
    /// required, since contention needs two roles to contend. The command
    /// line is split on whitespace with no shell-style quoting, so a path
    /// or argument containing a space will be mis-split.
    #[arg(long = "role")]
    role: Vec<String>,

    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Write the generated config here. Defaults to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Split a `--role name:cmd` argument into `(name, cmd)`.
fn parse_role_arg(s: &str) -> Result<(String, String)> {
    let (name, cmd) = s
        .split_once(':')
        .with_context(|| format!("`--role {s}` must be `name:command`"))?;
    if name.is_empty() || cmd.trim().is_empty() {
        bail!("`--role {s}` must be `name:command`, with both non-empty");
    }
    Ok((name.to_string(), cmd.to_string()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.role.len() < 2 {
        bail!("need at least two `--role name:cmd` entries to find contention between them");
    }

    let tracer = StraceTracer;
    let mut traces = Vec::new();
    for r in &args.role {
        let (name, cmd) = parse_role_arg(r)?;
        let comm =
            derive_comm(&cmd).with_context(|| format!("role `{name}` has an empty command"))?;
        let events = tracer
            .trace(&cmd)
            .with_context(|| format!("tracing role `{name}` (`{cmd}`)"))?;
        traces.push(RoleTrace { name, comm, events });
    }

    let config = build_config(args.scenario_id, args.cgroup, args.seed, &traces)?;

    // Round-trip through the engine's own parser: this is what makes the
    // output schema-valid by construction rather than by convention. The
    // exact validation `scx_crfuzz --config` applies runs here too, before
    // anything is written to disk.
    let json = config.to_json().context("serializing generated config")?;
    ScenarioConfig::from_json(&json)
        .context("generated config failed the engine's own validation -- this is a bug in scx_crfuzz_gen, not in your target")?;

    match args.output {
        Some(path) => std::fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("writing {}", path.display()))?,
        None => println!("{json}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_role_arg_splits_on_first_colon() {
        let (name, cmd) = parse_role_arg("victim:./victim /tmp/crfuzz/target").unwrap();
        assert_eq!(name, "victim");
        assert_eq!(cmd, "./victim /tmp/crfuzz/target");
    }

    #[test]
    fn parse_role_arg_rejects_a_missing_colon() {
        assert!(parse_role_arg("victim").is_err());
    }

    #[test]
    fn parse_role_arg_rejects_an_empty_command() {
        assert!(parse_role_arg("victim:   ").is_err());
    }

    #[test]
    fn parse_role_arg_rejects_an_empty_name() {
        assert!(parse_role_arg(":./victim").is_err());
    }
}
