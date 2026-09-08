use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ere_verifier_c)");
    println!("cargo:rerun-if-env-changed=ERE_VERIFIER_LIB_DIR");

    let Ok(lib_dir) = env::var("ERE_VERIFIER_LIB_DIR") else {
        return;
    };
    let lib_dir = PathBuf::from(lib_dir);
    let library = lib_dir.join("libere_verifier_c.a");
    assert!(
        library.is_file(),
        "ERE_VERIFIER_LIB_DIR does not contain libere_verifier_c.a: {}",
        lib_dir.display()
    );

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=ere_verifier_c");
    println!("cargo:rustc-cfg=ere_verifier_c");
}
