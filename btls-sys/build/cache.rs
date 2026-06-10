use std::{ffi::OsString, path::Path};

use crate::config::Config;

pub fn apply(_config: &Config, cfg: &mut cmake::Config) {
    try_enable_compiler_launcher(cfg);
}

fn try_enable_compiler_launcher(cfg: &mut cmake::Config) {
    if let Some(launcher) = compiler_launcher() {
        println!(
            "cargo:warning=using compiler launcher `{}` for the BoringSSL C/C++ build",
            launcher.to_string_lossy()
        );
        cfg.define("CMAKE_C_COMPILER_LAUNCHER", &launcher);
        cfg.define("CMAKE_CXX_COMPILER_LAUNCHER", &launcher);
        cfg.define("CMAKE_ASM_COMPILER_LAUNCHER", &launcher);
    }
}

fn compiler_launcher() -> Option<OsString> {
    println!("cargo:rerun-if-env-changed=BORING_BSSL_COMPILER_LAUNCHER");
    if let Some(launcher) =
        std::env::var_os("BORING_BSSL_COMPILER_LAUNCHER").filter(|v| !v.is_empty())
    {
        return Some(launcher);
    }

    for var in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
        println!("cargo:rerun-if-env-changed={var}");
        let Some(wrapper) = std::env::var_os(var).filter(|v| !v.is_empty()) else {
            continue;
        };
        let is_compiler_cache = Path::new(&wrapper)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| {
                stem.eq_ignore_ascii_case("sccache") || stem.eq_ignore_ascii_case("ccache")
            });
        if is_compiler_cache {
            return Some(wrapper);
        }
    }
    None
}
