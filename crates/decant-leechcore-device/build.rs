fn main() {
    println!("cargo:rerun-if-changed=src/leechcore_device.c");
    cc::Build::new()
        .file("src/leechcore_device.c")
        .warnings(true)
        .compile("decant_leechcore_abi");
}
