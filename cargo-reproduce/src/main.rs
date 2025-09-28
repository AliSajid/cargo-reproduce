use std::process::{Command, Stdio};
use std::path::PathBuf;
use std::fs;
use std::env;

use sha2::{Sha256, Digest};
use cargo_metadata::MetadataCommand;

/// Entry point for `cargo reproduce`.
/// Right now we only support:
/// - `cargo reproduce build [--strict]`
/// - `cargo reproduce verify`
fn main() {
    // Skip the first two args: "cargo" and "reproduce"
    let mut args = env::args().skip(2);

    match args.next().as_deref() {
        Some("build") => {
            // Optional flag for stricter reproducibility
            let strict = args.next().as_deref() == Some("--strict");
            repro_build(strict);
        }
        Some("verify") => repro_verify(),
        _ => {
            eprintln!("Usage: cargo reproduce <build|verify> [--strict]");
            std::process::exit(1);
        }
    }
}

/// Run `cargo build --release`, normalize the environment,
/// and save a reproducibility hash alongside the binary.
fn repro_build(strict: bool) {
    normalize_env(strict);

    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to run cargo build");

    if !status.success() {
        eprintln!("cargo build failed");
        std::process::exit(1);
    }

    let bin_name = get_package_name();
    if let Some(bin) = find_binary(&bin_name) {
        println!("🔍 Hashing binary: {}", bin.display());

        if strict {
            strip_binary(&bin);
        }

        let hash = sha256_file(&bin);
        println!("Reproducible build hash: {}", hash);

        // Save the hash so we can verify it later
        fs::write("target/repro-hash.txt", format!("{}\n", hash))
            .expect("failed to write hash file");
    } else {
        eprintln!("Binary for package '{}' not found in target/release", bin_name);
    }
}

/// Check that the current build still matches the saved hash.
fn repro_verify() {
    let bin_name = get_package_name();
    if let Some(bin) = find_binary(&bin_name) {
        println!("🔍 Verifying binary: {}", bin.display());
        let hash = sha256_file(&bin);

        match fs::read_to_string("target/repro-hash.txt") {
            Ok(saved) => {
                let saved = saved.trim();
                if hash == saved {
                    println!("✅ Verified: build matches saved hash ({})", hash);
                } else {
                    println!("❌ Mismatch!");
                    println!("  Current: {}", hash);
                    println!("  Saved:   {}", saved);
                    std::process::exit(1);
                }
            }
            Err(_) => {
                eprintln!("No repro-hash.txt found. Run `cargo reproduce build` first.");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Binary not found. Did you run `cargo reproduce build`?");
        std::process::exit(1);
    }
}

/// Set up the environment so builds are as deterministic as possible.
/// - Remaps paths to canonical placeholders
/// - Sets `SOURCE_DATE_EPOCH`
/// - Strips out user/machine-specific env vars
/// - Adds extra strict flags if requested
fn normalize_env(strict: bool) {
    if env::var("SOURCE_DATE_EPOCH").is_err() {
        unsafe { env::set_var("SOURCE_DATE_EPOCH", "0"); }
    }

    let cwd = env::current_dir().unwrap();
    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();

    // Replace absolute paths with stable placeholders
    rustflags.push_str(&format!(" --remap-path-prefix {}=.", cwd.display()));

    if let Ok(cargo_home) = env::var("CARGO_HOME") {
        rustflags.push_str(&format!(" --remap-path-prefix {}=.cargo-home", cargo_home));
    }

    rustflags.push_str(" --remap-path-prefix target=target");

    if let Ok(out_dir) = env::var("OUT_DIR") {
        rustflags.push_str(&format!(" --remap-path-prefix {}=.out", out_dir));
    }

    if let Ok(home) = env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        rustflags.push_str(&format!(" --remap-path-prefix {}=.home", home));
    }

    // Extra strict mode: disable debug info and timestamps
    if strict {
        rustflags.push_str(" -C debuginfo=0");

        if cfg!(target_os = "windows") {
            // On MSVC, /Breproduce removes timestamps from PE headers
            rustflags.push_str(" -C link-arg=/Breproduce");
        } else {
            // On LLD/GNU, disable build IDs and timestamps explicitly
            rustflags.push_str(" -C link-arg=-Wl,--build-id=none -C link-arg=-Wl,--no-insert-timestamp");
        }
    }

    unsafe { env::set_var("RUSTFLAGS", rustflags.trim()); }

    // Kill common env vars that can sneak into builds
    for var in ["USERNAME", "USER", "HOSTNAME", "COMPUTERNAME"] {
        unsafe { env::remove_var(var); }
    }

    println!("🔧 Normalized environment with RUSTFLAGS={}", rustflags.trim());
}

/// Grab the crate name from Cargo metadata.
/// (This way we don’t hardcode the binary name.)
fn get_package_name() -> String {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("failed to fetch cargo metadata");
    metadata.root_package().unwrap().name.to_string()
}

/// Look for the built binary in target/release
fn find_binary(bin_name: &str) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) {
        format!("{}.exe", bin_name.replace('-', "_"))
    } else {
        bin_name.replace('-', "_")
    };

    let candidate = PathBuf::from("target/release").join(exe_name);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Run `llvm-strip` on the binary to remove nondeterministic sections.
/// (If llvm-strip isn’t installed, just warn and continue.)
fn strip_binary(path: &PathBuf) {
    println!("🔧 Stripping binary metadata with llvm-strip: {}", path.display());
    let status = Command::new("llvm-strip")
        .arg("--strip-all")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => println!("✅ Binary stripped successfully"),
        _ => eprintln!("⚠️  Warning: llvm-strip not available or failed"),
    }
}

/// Compute a SHA256 hash of the binary’s contents.
fn sha256_file(path: &PathBuf) -> String {
    let mut file = fs::File::open(path).expect("cannot open file");
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).expect("failed to read file");
    format!("{:x}", hasher.finalize())
}
