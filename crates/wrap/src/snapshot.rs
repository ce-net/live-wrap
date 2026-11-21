//! `wrap.snapshot`: the app's state dirs as one archive, sealed. `restore` refuses an archive whose bytes or seal
//! do not match.
//!
//! The seal is a one-link chain from the snapshot key naming `snapshot:<app>:<sha256 of the archive>`. The key's
//! seed lives in the keys cell (`WRAP_SNAPSHOT_SEED` under `keys run`); restore needs only its public half.
use serde::{Deserialize, Serialize};
use shop_chain::{Caveats, Chain, Identity};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub app: String,
    pub archive: String,
    pub sha256: String,
    pub bytes: u64,
    pub dirs: Vec<String>,
    pub at: u64,
    pub seal: Chain,
}

fn sha_file(p: &Path) -> Result<(String, u64), String> {
    use sha2::{Digest, Sha256};
    let b = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok((hex::encode(Sha256::digest(&b)), b.len() as u64))
}

fn right(app: &str, sha: &str) -> String {
    format!("snapshot:{app}:{sha}")
}

/// Archive `dirs` of `state` (the app's host data dir) into `out`, sealed with `key`.
pub fn take(app: &str, state: &Path, dirs: &[String], out: &Path, key: &Identity) -> Result<PathBuf, String> {
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let at = shop_chain::now();
    let archive = out.join(format!("{app}-{at}.tar.gz"));
    let st = Command::new("tar").arg("-czf").arg(&archive).arg("-C").arg(state).args(dirs).status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err(format!("tar exited {st}"));
    }
    let (sha256, bytes) = sha_file(&archive)?;
    let seal = Chain::root(key, "snapshot", vec![right(app, &sha256)], Caveats { tenant: app.into(), until: u64::MAX / 2, ..Default::default() });
    let m = Manifest { app: app.into(), archive: archive.file_name().unwrap().to_string_lossy().into(), sha256, bytes, dirs: dirs.to_vec(), at, seal };
    let mp = out.join(format!("{app}-{at}.manifest.json"));
    std::fs::write(&mp, serde_json::to_vec_pretty(&m).unwrap()).map_err(|e| e.to_string())?;
    Ok(mp)
}

/// Check a manifest and its archive against the snapshot key; `Ok` gives the archive path.
pub fn verify(manifest: &Path, key_hex: &str, app: &str) -> Result<(Manifest, PathBuf), String> {
    let m: Manifest = serde_json::from_slice(&std::fs::read(manifest).map_err(|e| e.to_string())?).map_err(|e| format!("manifest: {e}"))?;
    if m.app != app {
        return Err(format!("snapshot is of {}, not {app}", m.app));
    }
    if m.seal.0.len() != 1 {
        return Err("seal is one link from the snapshot key".into());
    }
    let v = m.seal.verify(key_hex, shop_chain::now()).map_err(|e| format!("seal: {}", e.0))?;
    if v.rights != vec![right(app, &m.sha256)] {
        return Err("seal does not name this archive".into());
    }
    if m.archive.contains('/') || m.archive.contains("..") {
        return Err("archive name".into());
    }
    let archive = manifest.parent().unwrap_or(Path::new(".")).join(&m.archive);
    let (sha, _) = sha_file(&archive)?;
    if sha != m.sha256 {
        return Err(format!("archive sha256 {}… does not match the sealed {}…", &sha[..12], &m.sha256[..12]));
    }
    Ok((m, archive))
}

/// Restore into `state`, which must be absent or empty.
pub fn restore(manifest: &Path, key_hex: &str, app: &str, state: &Path) -> Result<Manifest, String> {
    let (m, archive) = verify(manifest, key_hex, app)?;
    if state.exists() && std::fs::read_dir(state).map_err(|e| e.to_string())?.next().is_some() {
        return Err(format!("{} is not empty: remove the app first", state.display()));
    }
    std::fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let st = Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(state).arg("--no-same-owner").status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err(format!("tar exited {st}"));
    }
    Ok(m)
}
