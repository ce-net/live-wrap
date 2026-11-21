//! A catalog entry: the whole thing a contributor writes to add an app.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub app: App,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub name: String,
    pub image: String,
    pub http: Http,
    pub state: State,
    pub auth: Auth,
    pub limits: Limits,
    pub skill: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub placement: Placement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http {
    pub port: u16,
    pub health: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub dirs: Vec<String>,
    pub mount: String,
    pub snapshot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub passkey: bool,
    /// the header the app trusts for the signed-in user; empty = the app has no login of its own
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub bootstrap: String,
    #[serde(default)]
    pub oidc: bool,
    #[serde(default)]
    pub trusted_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub cpu: String,
    pub mem: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    #[serde(default)]
    pub needs: Vec<String>,
}

pub fn load(path: &Path) -> Result<App, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let e: Entry = toml::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(e.app)
}

pub fn all(dir: &Path) -> Result<Vec<(std::path::PathBuf, App)>, String> {
    let mut v = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "toml")).collect();
    paths.sort();
    for p in paths {
        let a = load(&p)?;
        v.push((p, a));
    }
    Ok(v)
}

/// CPU as docker's `--cpus` (`"150%"` -> 1.5).
pub fn cpus(s: &str) -> Option<f64> {
    s.strip_suffix('%')?.parse::<f64>().ok().map(|p| p / 100.0).filter(|c| *c > 0.0 && *c <= 64.0)
}

/// Memory in bytes (`"512M"`, `"2G"`).
pub fn mem_bytes(s: &str) -> Option<u64> {
    let (n, mul) = match s.chars().last()? {
        'K' => (&s[..s.len() - 1], 1u64 << 10),
        'M' => (&s[..s.len() - 1], 1 << 20),
        'G' => (&s[..s.len() - 1], 1 << 30),
        _ => return None,
    };
    n.parse::<u64>().ok().map(|n| n * mul).filter(|b| *b >= 16 << 20)
}

/// Every rule an entry must meet. Empty = it lints.
pub fn lint(file: &Path, a: &App) -> Vec<String> {
    let mut e = Vec::new();
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if a.name != stem {
        e.push(format!("name {} differs from the file name {stem}", a.name));
    }
    if a.name.is_empty() || !a.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        e.push("name is lowercase letters, digits and -".into());
    }
    let digest = a.image.contains("@sha256:");
    let tag = a.image.rsplit('/').next().is_some_and(|last| last.contains(':') && !last.ends_with(":latest"));
    if !digest && !tag {
        e.push("image needs an exact tag or a sha256 digest (never :latest or no tag)".into());
    }
    if !a.image.contains('/') || !a.image.split('/').next().unwrap_or("").contains('.') {
        e.push("image names its registry (docker.io/..., ghcr.io/...)".into());
    }
    if a.http.port == 0 {
        e.push("http.port is the port inside the container".into());
    }
    if !a.http.health.starts_with('/') {
        e.push("http.health is a path".into());
    }
    if a.state.dirs.is_empty() || a.state.dirs.iter().any(|d| d.is_empty() || d.contains("..") || d.starts_with('/')) {
        e.push("state.dirs are relative names under the mount (\".\" = all of it), at least one".into());
    }
    if !a.state.mount.starts_with('/') {
        e.push("state.mount is an absolute path in the container".into());
    }
    if !["nightly", "hourly", "never"].contains(&a.state.snapshot.as_str()) {
        e.push("state.snapshot is nightly, hourly or never".into());
    }
    if !a.auth.passkey {
        e.push("auth.passkey must be true: every wrapped app sits behind the passkey forward-auth".into());
    }
    if !a.auth.header.is_empty() && !a.auth.header.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        e.push("auth.header is a header name".into());
    }
    if cpus(&a.limits.cpu).is_none() {
        e.push("limits.cpu is a percent of one core, like 100%".into());
    }
    if mem_bytes(&a.limits.mem).is_none() {
        e.push("limits.mem is like 512M or 2G (at least 16M)".into());
    }
    if a.skill.trim().is_empty() {
        e.push("skill says what the app is and where its API is".into());
    }
    for (k, v) in &a.env {
        let low = k.to_ascii_lowercase();
        if (low.contains("password") || low.contains("secret") || low.contains("token")) && !v.is_empty() {
            e.push(format!("env {k}: secrets live in the keys cell, not in the catalog"));
        }
    }
    e
}
