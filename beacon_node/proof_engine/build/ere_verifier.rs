use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

const ERE_VERSION: &str = "v0.18.0";
const LIBRARY_FILENAME: &str = "libere_verifier_c.a";

struct Artifact {
    archive_filename: &'static str,
    sha256: &'static str,
}

pub fn configure() -> Result<(), Box<dyn Error>> {
    let target = env::var("TARGET")?;
    let artifact = artifact_for_target(&target).ok_or_else(|| {
        format!(
            "feature `ere-verifier` is not supported for target `{target}`; supported targets are \
             aarch64-apple-darwin, x86_64-unknown-linux-gnu, and aarch64-unknown-linux-gnu"
        )
    })?;

    let cache_root = env::var_os("ERE_VERIFIER_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo")));
    let artifact_dir = cache_root
        .join("ere-verifier")
        .join(ERE_VERSION)
        .join(target);
    fs::create_dir_all(&artifact_dir)?;

    let archive_path = artifact_dir.join(artifact.archive_filename);
    ensure_archive(artifact, &archive_path)?;

    let library_path = artifact_dir.join(LIBRARY_FILENAME);
    extract_library(&archive_path, &library_path)?;

    println!("cargo:rustc-link-search=native={}", artifact_dir.display());
    println!("cargo:rustc-link-lib=static=ere_verifier_c");
    Ok(())
}

fn artifact_for_target(target: &str) -> Option<&'static Artifact> {
    static DARWIN_ARM64: Artifact = Artifact {
        archive_filename: "libere_verifier_c.darwin-arm64.tar.gz",
        sha256: "764dedba66690f105b797be6ba8a485f1c53ed8d3a0fcdef15d350ab2fc3ef7d",
    };
    static LINUX_AMD64: Artifact = Artifact {
        archive_filename: "libere_verifier_c.linux-amd64.tar.gz",
        sha256: "9e619994126aa9f7632bea6fce02659aa3ff8bc202e5e017dd21abf967210026",
    };
    static LINUX_ARM64: Artifact = Artifact {
        archive_filename: "libere_verifier_c.linux-arm64.tar.gz",
        sha256: "1b6acdfdaf02ffb84fabb1ea081fc88443f194cf60f767827ff1c60393ececf2",
    };

    match target {
        "aarch64-apple-darwin" => Some(&DARWIN_ARM64),
        "x86_64-unknown-linux-gnu" => Some(&LINUX_AMD64),
        "aarch64-unknown-linux-gnu" => Some(&LINUX_ARM64),
        _ => None,
    }
}

fn ensure_archive(artifact: &Artifact, archive_path: &Path) -> Result<(), Box<dyn Error>> {
    if archive_path.is_file() {
        if file_sha256(archive_path)? == artifact.sha256 {
            return Ok(());
        }
        fs::remove_file(archive_path)?;
    }

    let url = format!(
        "https://github.com/eth-act/ere/releases/download/{ERE_VERSION}/{}",
        artifact.archive_filename
    );
    let temporary_path = archive_path.with_extension(format!("download-{}", std::process::id()));
    let mut response = reqwest::blocking::Client::builder()
        .user_agent("lighthouse-proof-engine-build")
        .build()?
        .get(&url)
        .send()?
        .error_for_status()?;
    let mut output = File::create(&temporary_path)?;
    io::copy(&mut response, &mut output)?;
    output.sync_all()?;

    let actual_sha256 = file_sha256(&temporary_path)?;
    if actual_sha256 != artifact.sha256 {
        fs::remove_file(&temporary_path)?;
        return Err(format!(
            "checksum mismatch for `{url}`: expected {}, received {actual_sha256}",
            artifact.sha256
        )
        .into());
    }

    if let Err(error) = fs::rename(&temporary_path, archive_path) {
        if archive_path.is_file() && file_sha256(archive_path)? == artifact.sha256 {
            fs::remove_file(&temporary_path)?;
        } else {
            return Err(error.into());
        }
    }

    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn extract_library(archive_path: &Path, library_path: &Path) -> Result<(), Box<dyn Error>> {
    let decoder = flate2::read::GzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    let temporary_path = library_path.with_extension(format!("extract-{}", std::process::id()));

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.file_name() == Some(OsStr::new(LIBRARY_FILENAME)) {
            let mut output = File::create(&temporary_path)?;
            io::copy(&mut entry, &mut output)?;
            output.sync_all()?;
            fs::rename(&temporary_path, library_path)?;
            return Ok(());
        }
    }

    Err(format!(
        "`{}` does not contain `{LIBRARY_FILENAME}`",
        archive_path.display()
    )
    .into())
}
