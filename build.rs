use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=wrapper.c");
    println!("cargo:rerun-if-env-changed=LIBFABRIC_DIR");
    println!("cargo:rerun-if-env-changed=LIBFABRIC_PREFIX");
    println!("cargo:rerun-if-env-changed=LIBFABRIC_INCLUDE");

    let mut include_paths: Vec<PathBuf> = Vec::new();

    // Try to find libfabric using pkg-config first
    let libfabric_via_pkg = pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("libfabric");

    match libfabric_via_pkg {
        Ok(library) => {
            println!("cargo:warning=Found libfabric via pkg-config");

            // pkg-config already prints cargo metadata for linking.
            // We just reuse its include paths for cc and bindgen.
            include_paths.extend(library.include_paths);
        }
        Err(err) => {
            println!(
                "cargo:warning=pkg-config could not find libfabric ({}); falling back to manual detection",
                err
            );

            // Determine libfabric directory from env or common locations
            let libfabric_dir = env::var("LIBFABRIC_DIR")
                .or_else(|_| env::var("LIBFABRIC_PREFIX"))
                .unwrap_or_else(|_| {
                    for root in &["/opt/amazon/efa", "/usr", "/usr/local"] {
                        let lib64 = format!("{}/lib64/libfabric.so", root);
                        let lib = format!("{}/lib/libfabric.so", root);
                        if Path::new(&lib64).exists() || Path::new(&lib).exists() {
                            return root.to_string();
                        }
                    }
                    "/usr".to_string()
                });

            println!("cargo:warning=Using libfabric from {}", libfabric_dir);

            for lib_dir in &["lib64", "lib"] {
                let full = format!("{}/{}", &libfabric_dir, lib_dir);
                println!("cargo:rustc-link-search=native={}", full);
            }
            println!("cargo:rustc-link-lib=dylib=fabric");

            let include_dir = PathBuf::from(format!("{}/include", libfabric_dir));
            if include_dir.exists() {
                include_paths.push(include_dir);
            }
        }
    }

    // LIBFABRIC_INCLUDE env var can provide additional/override include paths (colon-separated)
    if let Ok(env_includes) = env::var("LIBFABRIC_INCLUDE") {
        for path in env_includes.split(':').filter(|p| !p.is_empty()) {
            include_paths.push(PathBuf::from(path));
        }
    }

    // Add common system locations as fallback
    for dir in &[
        "/opt/amazon/efa/include",
        "/usr/include",
        "/usr/local/include",
    ] {
        let p = PathBuf::from(dir);
        if p.exists() {
            include_paths.push(p);
        }
    }

    // Deduplicate include paths
    let mut seen = HashSet::new();
    include_paths.retain(|p| {
        let s = p.display().to_string();
        if seen.contains(&s) {
            false
        } else {
            seen.insert(s);
            true
        }
    });

    // Compile wrapper.c with cc, using the resolved include paths
    let mut build = cc::Build::new();
    build.file("wrapper.c");
    for p in &include_paths {
        build.include(p);
    }
    build.compile("wrapper");

    // Generate bindings with bindgen, using the same include paths
    let mut bindgen_builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for p in &include_paths {
        bindgen_builder = bindgen_builder.clang_arg(format!("-I{}", p.display()));
    }

    let bindings = bindgen_builder
        .generate()
        .expect("Unable to generate bindings for libfabric via bindgen");

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
