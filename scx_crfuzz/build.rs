fn main() {
    #[cfg(target_os = "linux")]
    {
        scx_cargo::BpfBuilder::new()
            .unwrap()
            .enable_skel("src/bpf/main.bpf.c", "bpf")
            .build()
            .unwrap();
        // The containerd target's mutator, embedded in the binary: static, so it
        // runs in the held task's view, the container's rootfs included.
        let src = "tests/fixtures/mutator_all.c";
        let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("mutator_all");
        println!("cargo:rerun-if-changed={src}");
        let st = std::process::Command::new(cc::Build::new().get_compiler().path())
            .args(["-O2", "-static", "-o"])
            .arg(&out)
            .arg(src)
            .status()
            .expect("run the C compiler");
        assert!(st.success(), "{src}: static link failed; install a static libc (Fedora: glibc-static, Debian/Ubuntu: libc6-dev)");
    }
}
