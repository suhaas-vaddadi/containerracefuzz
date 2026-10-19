use std::path::PathBuf;
use std::process::Command;

pub fn trigger_file(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(name);
    std::fs::write(&p, "").unwrap();
    p
}

/// Build the Go fixture in `tests/fixtures/<dir>`.
pub fn go_bin(dir: &str) -> PathBuf {
    let out = std::env::temp_dir().join(format!("crfuzz_{dir}"));
    let src = format!("{}/tests/fixtures/{dir}", env!("CARGO_MANIFEST_DIR"));
    let ok = Command::new("go").args(["build", "-o"]).arg(&out).current_dir(src).status().unwrap().success();
    assert!(ok, "go build failed");
    out
}
