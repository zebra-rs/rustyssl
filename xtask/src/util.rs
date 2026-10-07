//! Helpers shared by xtask commands.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The workspace root: the parent of this crate's directory.
pub fn workspace_root() -> PathBuf {
    let xtask = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask.parent().unwrap_or(xtask).to_path_buf()
}

/// Deletes `dir` if it exists and creates it again, empty.
pub fn fresh_dir(dir: &Path) -> Result {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    Ok(())
}

/// Creates `dir` readable only by the current user, as GnuPG requires for its home directory.
pub fn private_dir(dir: &Path) -> Result {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Returns `path` with `suffix` appended to its file name (`a.tar.gz` -> `a.tar.gz.asc`).
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

/// Runs `cmd`, appending its stdout and stderr to `log`. On failure, the error names the log.
pub fn run_logged(cmd: &mut Command, log: &Path) -> Result {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let out = OpenOptions::new().create(true).append(true).open(log)?;
    let status = cmd
        .stdout(out.try_clone()?)
        .stderr(out)
        .status()
        .map_err(|e| format!("cannot run `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program}` failed ({status}); see {}", log.display()).into())
    }
}

/// Lowercase hex SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(
            buf.get(..n)
                .ok_or("read returned more bytes than the buffer holds")?,
        );
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Copies `from` to `to`, creating the parent directories of `to`.
pub fn copy_file(from: &Path, to: &Path) -> Result {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to).map_err(|e| format!("cannot copy {}: {e}", from.display()))?;
    Ok(())
}
