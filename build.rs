// Windows shows an executable's icon in Explorer, the taskbar and the window
// switcher, and it comes from a resource compiled into the file. Nothing else
// needs a build script, so every other platform gets an empty one.
//
// The resource id (1) is also what the desktop window loads its own icon from in
// src/bin/sniper-desktop.rs; change them together.
#[cfg(windows)]
fn main() {
    use std::{env, fs, path::PathBuf};

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=packaging/windows/sniper.ico");

    // The script is written here, not kept in the repository, so the icon's path
    // can be absolute: where a relative ICON path is looked up depends on the
    // resource compiler's working directory.
    let icon = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"))
        .join("packaging/windows/sniper.ico");
    let script = PathBuf::from(env::var_os("OUT_DIR").expect("set by cargo")).join("sniper.rc");
    fs::write(
        &script,
        format!(
            "1 ICON \"{}\"\n",
            icon.display().to_string().replace('\\', "/")
        ),
    )
    .expect("could not write the resource script");
    embed_resource::compile(&script, embed_resource::NONE)
        .manifest_required()
        .expect("could not embed the Sniper icon");
}

#[cfg(not(windows))]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
