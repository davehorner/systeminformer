use std::env;
use std::path::PathBuf;

fn main() {
    let mut cfg = cc::Build::new();
    cfg.include("../phlib/include") // Include path for ph.h
       .include("../phnt/include") // Include path for phnt headers
       .include("../kphlib/include") // Include path for kphuser.h
       .define("BUILDING_PHLIB", "1") // Define macro to fix dllimport/export
       .flag("-wd4706") // Suppress assignment warnings
       .flag("-wd4273") // Suppress inconsistent DLL linkage warnings
       .flag("-wd4013") // Suppress undefined function warnings
       .flag_if_supported("/std:c++17"); // Enable C++17

    // Compile only native.c
    cfg.file("../phlib/native.c");
    cfg.compile("phlib");

    // Generate bindings for ph.h and kphuser.h
    let bindings = bindgen::Builder::default()
        .header("../phlib/include/ph.h") // Include ph.h
        .header("../phlib/include/kphuser.h") // Include ph.h
        // .header("../kphlib/include/kphuser.h") // Include kphuser.h
        .clang_arg("-I../phlib/include") // Path to ph.h
        .clang_arg("-I../phnt/include") // Path to phnt headers
        .clang_arg("-I../kphlib/include") // Path to kphuser.h
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .layout_tests(false) // Disable layout tests if they cause issues
        .generate_comments(false) // Disable comments if they cause issues
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the output directory
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("bindings.rs")).unwrap();

    // Link the kphlib library
    println!("cargo:rustc-link-search=native=../kphlib/lib"); // Path to kphlib
    println!("cargo:rustc-link-lib=static=kphlib"); // Link the static library
}