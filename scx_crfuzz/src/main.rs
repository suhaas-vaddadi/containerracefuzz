//! scx_crfuzz: `--help` has the commands, the README the rest.

#[cfg(target_os = "linux")]
mod campaign;
#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod run;
#[cfg(target_os = "linux")]
mod targets {
    pub mod containerd;
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(cli::main(std::env::args().skip(1).collect()));
}
