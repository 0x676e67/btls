use crate::run_command;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

// `CARGO_CRATE_NAME` is `build_script_main` here, so derive the C identifier
// from the package name instead.
pub(crate) static PREFIX: LazyLock<String> =
    LazyLock::new(|| env!("CARGO_PKG_NAME").replace('-', "_"));

#[derive(Debug)]
pub(crate) struct PrefixCallback;

impl bindgen::callbacks::ParseCallbacks for PrefixCallback {
    fn generated_link_name_override(
        &self,
        item_info: bindgen::callbacks::ItemInfo<'_>,
    ) -> Option<String> {
        Some(format!("{}_{}", PREFIX.as_str(), item_info.name))
    }
}

pub(crate) fn regenerate_prefix_symbols(source_path: &Path, out_dir: &Path) -> io::Result<()> {
    let source_root = boringssl_source_root(source_path)?;
    let generator_root = out_dir.join("prefix-symbol-generator");
    prepare_generator_workspace(&source_root, &generator_root)?;

    // Project patches add public APIs which are not present in BoringSSL's checked-in
    // prefix list. Use BoringSSL's generator so the native build prefixes those APIs too.
    run_command(
        Command::new("go")
            .args([
                "run",
                "./util/pregenerate",
                "include/openssl/prefix_symbols.h",
            ])
            .current_dir(&generator_root),
    )?;

    fs::copy(
        generator_root.join("include/openssl/prefix_symbols.h"),
        source_root.join("include/openssl/prefix_symbols.h"),
    )?;
    fs::remove_dir_all(generator_root)?;

    Ok(())
}

pub(crate) fn audit_prefixed_symbols(
    source_path: &Path,
    archive_path: &Path,
    target_os: &str,
) -> io::Result<()> {
    let Some(object_format) = object_file_format(target_os) else {
        println!(
            "cargo:warning=BoringSSL's symbol audit does not support the {target_os} object format"
        );
        return Ok(());
    };
    let source_root = boringssl_source_root(source_path)?;

    run_command(
        Command::new("go")
            .args([
                "run",
                "./util/audit_symbols.go",
                "-obj-file-format",
                object_format,
                "-ignore-symbols-with",
                PREFIX.as_str(),
            ])
            .arg(archive_path)
            .current_dir(source_root),
    )?;

    Ok(())
}

pub(crate) fn find_crypto_archive(
    build_dir: &Path,
    target_env: &str,
    msvc_lib_subdir: Option<&str>,
) -> io::Result<PathBuf> {
    let library_name = if target_env == "msvc" {
        "crypto.lib"
    } else {
        "libcrypto.a"
    };
    let mut candidates = Vec::new();

    for subdir in ["lib", "crypto", ""] {
        let dir = build_dir.join(subdir);
        if let Some(msvc_subdir) = msvc_lib_subdir {
            candidates.push(dir.join(msvc_subdir).join(library_name));
        }
        candidates.push(dir.join(library_name));
    }

    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .ok_or_else(|| {
            let searched = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not find BoringSSL's crypto archive; searched: {searched}"),
            )
        })
}

fn prepare_generator_workspace(source_root: &Path, generator_root: &Path) -> io::Result<()> {
    if generator_root.exists() {
        fs::remove_dir_all(generator_root)?;
    }
    fs::create_dir_all(generator_root)?;

    for path in [
        "include",
        "util/build",
        "util/idextractor",
        "util/pregenerate",
    ] {
        let source = source_root.join(path);
        let destination = Path::new(path).parent().map_or_else(
            || generator_root.to_owned(),
            |parent| generator_root.join(parent),
        );
        fs::create_dir_all(&destination)?;
        fs_extra::dir::copy(source, destination, &Default::default()).map_err(io::Error::other)?;
    }

    for file in ["go.mod", "go.sum"] {
        fs::copy(source_root.join(file), generator_root.join(file))?;
    }
    // BoringSSL's pregenerator uses this file only to confirm its working directory.
    fs::write(generator_root.join("BUILDING.md"), [])?;
    fs::write(
        generator_root.join("build.json"),
        prefix_build_json(source_root)?,
    )?;

    Ok(())
}

fn prefix_build_json(source_root: &Path) -> io::Result<String> {
    // pregenerate's prefix task consumes Hdrs before expanding globs, so each
    // public header must be listed explicitly.
    let mut headers = Vec::new();
    for entry in fs::read_dir(source_root.join("include/openssl"))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension().is_none_or(|ext| ext != "h") {
            continue;
        }

        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 public header"))?;
        if name.starts_with("prefix_symbols") {
            continue;
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported character in public header name: {name}"),
            ));
        }
        headers.push(format!("include/openssl/{name}"));
    }
    headers.sort_unstable();

    if headers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no BoringSSL public headers found",
        ));
    }

    let headers = headers
        .iter()
        .map(|header| format!("            \"{header}\""))
        .collect::<Vec<_>>()
        .join(",\n");
    Ok(format!(
        "{{\n    \"crypto\": {{\n        \"prefix_symbols\": true,\n        \"hdrs\": [\n{headers}\n        ]\n    }}\n}}\n"
    ))
}

fn object_file_format(target_os: &str) -> Option<&'static str> {
    match target_os {
        "android" | "dragonfly" | "freebsd" | "haiku" | "illumos" | "linux" | "netbsd"
        | "openbsd" | "solaris" => Some("elf"),
        "ios" | "macos" | "tvos" | "visionos" | "watchos" => Some("macho"),
        "windows" => Some("pe"),
        _ => None,
    }
}

fn boringssl_source_root(source_path: &Path) -> io::Result<PathBuf> {
    for candidate in [source_path.to_owned(), source_path.join("src")] {
        if candidate.join("util/pregenerate").is_dir() {
            return Ok(candidate);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "could not find BoringSSL's util/pregenerate under {}",
            source_path.display()
        ),
    ))
}
