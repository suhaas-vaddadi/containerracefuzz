//! scx_crfuzz [--seed N] [--mutator PROG] -- CMD [ARGS...]
//!
//! Run CMD under POS (discovery) and print the decision log. With
//! `--mutator`, PROG (a binary or a script with a #!) runs at every hold
//! whose event has a known path, as the held task: its uid and namespaces,
//! its root and cwd, the path as issued in argv[1] (D6). Needs root and a
//! running scx_crfuzz_gated.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    use scx_crfuzz::{backend::GateBackend, engine, pos::Pos};
    use std::process::Command;
    use std::time::{Duration, Instant};

    const USAGE: &str = "usage: scx_crfuzz [--seed N] [--mutator PROG] -- CMD [ARGS...]";
    // ponytail: a fixed watch set (the path syscalls D3 decodes, minus execve,
    // which needs CMD as a path) and fixed timing; flags when a scenario needs them.
    const WATCHED: &[i64] = &[
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlinkat,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_chdir,
    ];

    let mut args = std::env::args().skip(1);
    let (mut seed, mut mutator) = (0u64, None);
    let cmd: Vec<String> = loop {
        match args.next().as_deref() {
            Some("--seed") => seed = args.next().context(USAGE)?.parse().context("--seed")?,
            // Absolute: the mutator is exec'd after a chdir into the task's cwd.
            Some("--mutator") => mutator = Some(std::fs::canonicalize(args.next().context(USAGE)?).context("--mutator")?),
            Some("--") => break args.collect(),
            _ => bail!(USAGE),
        }
    };
    let (prog, rest) = cmd.split_first().context(USAGE)?;
    let mut sut = Command::new(prog);
    sut.args(rest);
    let mut be = GateBackend::spawn(sut, WATCHED)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let ms = Duration::from_millis;
    let log = engine::run(&mut be, &mut Pos::new(seed), mutator.as_deref(), ms(1), ms(200), deadline)?;
    for d in &log {
        println!("{d:?}");
    }
    let code = be.child().wait()?.code().unwrap_or(1);
    drop(be); // exit() skips Drop, which clears our gates and cgroup
    std::process::exit(code)
}
