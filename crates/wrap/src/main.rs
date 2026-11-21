use std::path::{Path, PathBuf};
use std::process::Command;
use wrap::{auth, catalog, snapshot};

const USAGE: &str = "usage: ce-wrap <command>
  list                          the catalog's apps
  lint                          check every entry (exit 1 on any problem)
  dry-run <app>                 the container and the auth route `up` would make, without running anything
  pin <app>                     pull the image and write its sha256 digest into the entry
  up <app> [--port P]           start the container (CPU and memory capped, port on 127.0.0.1 only)
  auth <app> --bind A --upstream U    serve the passkey forward-auth (WRAP_ISSUER = the issuer's public key)
  session <app> <user> [--ttl S]      issue a session (WRAP_ISSUER_SEED; in ce: account-passkey after a login)
  snapshot <app>                take a sealed snapshot of the app's state (WRAP_SNAPSHOT_SEED)
  rm <app>                      remove the container and its state (take a snapshot first)
  restore <app> --from <manifest>     verify (WRAP_SNAPSHOT_PUB) and restore into the empty state dir
  keygen                        a new key pair (the seed goes into the keys cell)
env: WRAP_CATALOG (default ./catalog), WRAP_HOME (default ~/.local/share/live-wrap)";

fn flag(a: &[String], n: &str) -> Option<String> {
    a.iter().position(|x| x == n).and_then(|i| a.get(i + 1).cloned())
}

fn catalog_dir() -> PathBuf {
    std::env::var("WRAP_CATALOG").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("catalog"))
}

fn home() -> PathBuf {
    std::env::var("WRAP_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share/live-wrap"))
}

fn entry(app: &str) -> Result<(PathBuf, catalog::App), String> {
    let p = catalog_dir().join(format!("{app}.toml"));
    let a = catalog::load(&p)?;
    let errs = catalog::lint(&p, &a);
    if !errs.is_empty() {
        return Err(format!("{}: {}", p.display(), errs.join("; ")));
    }
    Ok((p, a))
}

fn id(var: &str) -> Result<shop_chain::Identity, String> {
    let s = std::env::var(var).map_err(|_| format!("{var} is not set (run under `keys run`)"))?;
    Ok(shop_chain::Identity::from_seed(shop_chain::hex_seed(s.trim()).ok_or(format!("{var} is not 64 hex"))?))
}

fn uid() -> String {
    let o = |a: &str| Command::new("id").arg(a).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    format!("{}:{}", o("-u"), o("-g"))
}

/// The `docker run` argv for an entry. Pure, so `dry-run` and `up` print and run the same thing.
pub fn run_argv(a: &catalog::App, state: &Path, host_port: u16, user: &str) -> Vec<String> {
    let mut v: Vec<String> = ["run", "-d", "--name"].iter().map(|s| s.to_string()).collect();
    v.push(format!("ce-wrap-{}", a.name));
    v.push(format!("--cpus={}", catalog::cpus(&a.limits.cpu).unwrap_or(1.0)));
    v.push(format!("--memory={}", catalog::mem_bytes(&a.limits.mem).unwrap_or(1 << 30)));
    v.extend(["--pids-limit=512".into(), "--security-opt=no-new-privileges".into(), "--cap-drop=ALL".into()]);
    v.push(format!("--user={user}"));
    v.push(format!("--publish=127.0.0.1:{host_port}:{}", a.http.port));
    v.push(format!("--volume={}:{}", state.display(), a.state.mount));
    v.push(format!("--label=ce.wrap.app={}", a.name));
    for (k, val) in &a.env {
        v.push(format!("--env={k}={val}"));
    }
    v.push(a.image.clone());
    v.extend(a.args.iter().cloned());
    v
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

fn health(port: u16, path: &str, secs: u64) -> Result<u64, String> {
    let t0 = std::time::Instant::now();
    while t0.elapsed().as_secs() < secs {
        let o = Command::new("curl").args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3"]).arg(format!("http://127.0.0.1:{port}{path}")).output();
        if let Ok(o) = o {
            if String::from_utf8_lossy(&o.stdout).starts_with('2') {
                return Ok(t0.elapsed().as_millis() as u64);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!("no 2xx from {path} in {secs} s"))
}

fn docker(args: &[String]) -> Result<String, String> {
    let o = Command::new("docker").args(args).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn run(a: &[String]) -> Result<(), String> {
    let cmd = a.first().map(String::as_str).unwrap_or("");
    let app = a.get(1).cloned().unwrap_or_default();
    match cmd {
        "list" => {
            for (_, e) in catalog::all(&catalog_dir())? {
                println!("{:<16} {:<56} auth={} {}", e.name, e.image, if e.auth.header.is_empty() { "forward-only" } else { &e.auth.header }, if e.placement.needs.is_empty() { String::new() } else { format!("needs {:?}", e.placement.needs) });
            }
        }
        "lint" => {
            let all = catalog::all(&catalog_dir())?;
            let mut bad = 0;
            for (p, e) in &all {
                let errs = catalog::lint(p, e);
                println!("{:<16} {}", e.name, if errs.is_empty() { "ok".to_string() } else { errs.join("; ") });
                bad += usize::from(!errs.is_empty());
            }
            if bad > 0 {
                return Err(format!("{bad} of {} entries do not lint", all.len()));
            }
        }
        "dry-run" => {
            let (_, e) = entry(&app)?;
            let state = home().join(&e.name);
            let mut argv = vec!["docker".to_string()];
            argv.extend(run_argv(&e, &state, 0, "<uid>:<gid>"));
            let plan = serde_json::json!({
                "app": e.name, "container": argv, "health": e.http.health,
                "auth": { "passkey": e.auth.passkey, "user_header": e.auth.header, "default": "deny" },
                "snapshot": { "dirs": e.state.dirs, "every": e.state.snapshot, "seal": "snapshot key in the keys cell" },
                "placement": e.placement.needs, "skill": e.skill,
            });
            println!("{}", serde_json::to_string_pretty(&plan).unwrap());
        }
        "pin" => {
            let (p, e) = entry(&app)?;
            let base = e.image.split('@').next().unwrap().to_string();
            docker(&["pull".into(), "-q".into(), base.clone()])?;
            let d = docker(&["image".into(), "inspect".into(), "--format".into(), "{{index .RepoDigests 0}}".into(), base.clone()])?;
            let digest = d.rsplit('@').next().unwrap_or("").to_string();
            if !digest.starts_with("sha256:") {
                return Err(format!("no digest for {base}: {d}"));
            }
            let pinned = format!("{base}@{digest}");
            let s = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
            std::fs::write(&p, s.replace(&format!("image = \"{}\"", e.image), &format!("image = \"{pinned}\""))).map_err(|e| e.to_string())?;
            println!("{pinned}");
        }
        "up" => {
            let (_, e) = entry(&app)?;
            if !e.placement.needs.is_empty() {
                return Err(format!("{} needs {:?}; this node is not tagged with it", e.name, e.placement.needs));
            }
            let state = home().join(&e.name);
            std::fs::create_dir_all(&state).map_err(|x| x.to_string())?;
            let port = flag(a, "--port").and_then(|p| p.parse().ok()).unwrap_or_else(free_port);
            let t0 = std::time::Instant::now();
            let cid = docker(&run_argv(&e, &state, port, &uid()))?;
            let ms = health(port, &e.http.health, 180)?;
            println!("{}", serde_json::json!({ "app": e.name, "container": &cid[..12.min(cid.len())], "upstream": format!("127.0.0.1:{port}"), "healthy_ms": ms, "total_ms": t0.elapsed().as_millis() as u64 }));
        }
        "auth" => {
            let (_, e) = entry(&app)?;
            let issuer_hex = std::env::var("WRAP_ISSUER").map_err(|_| "WRAP_ISSUER (the session issuer's public key) is not set")?;
            let bind = flag(a, "--bind").ok_or("--bind host:port")?;
            let upstream = flag(a, "--upstream").ok_or("--upstream host:port")?;
            let g = auth::Gate { app: e.name.clone(), issuer_hex, header: e.auth.header.clone(), upstream };
            eprintln!("wrap.auth for {} on {bind}: default deny", e.name);
            tokio::runtime::Runtime::new().unwrap().block_on(auth::serve(g, &bind)).map_err(|x| x.to_string())?;
        }
        "session" => {
            let user = a.get(2).ok_or("session <app> <user>")?;
            let ttl = flag(a, "--ttl").and_then(|t| t.parse().ok()).unwrap_or(3600);
            println!("{}", auth::issue(&id("WRAP_ISSUER_SEED")?, &app, user, ttl));
        }
        "snapshot" => {
            let (_, e) = entry(&app)?;
            let key = id("WRAP_SNAPSHOT_SEED")?;
            // a running app is stopped for the archive (its database files must be quiet) and started again after
            let name = format!("ce-wrap-{}", e.name);
            let was_running = docker(&["inspect".into(), "--format".into(), "{{.State.Running}}".into(), name.clone()]).map(|s| s == "true").unwrap_or(false);
            if was_running {
                docker(&["stop".into(), "-t".into(), "20".into(), name.clone()])?;
            }
            let m = snapshot::take(&e.name, &home().join(&e.name), &e.state.dirs, &home().join("snapshots"), &key);
            if was_running {
                docker(&["start".into(), name])?;
            }
            println!("{}", m?.display());
        }
        "rm" => {
            let (_, e) = entry(&app)?;
            let _ = docker(&["rm".into(), "-f".into(), format!("ce-wrap-{}", e.name)]);
            let state = home().join(&e.name);
            if state.exists() {
                std::fs::remove_dir_all(&state).map_err(|x| format!("{}: {x}", state.display()))?;
            }
            println!("removed ce-wrap-{} and {}", e.name, state.display());
        }
        "restore" => {
            let (_, e) = entry(&app)?;
            let from = flag(a, "--from").ok_or("--from <manifest>")?;
            let key = std::env::var("WRAP_SNAPSHOT_PUB").map_err(|_| "WRAP_SNAPSHOT_PUB is not set")?;
            let m = snapshot::restore(Path::new(&from), &key, &e.name, &home().join(&e.name))?;
            println!("{}", serde_json::json!({ "restored": e.name, "sha256": m.sha256, "bytes": m.bytes, "taken_at": m.at }));
        }
        "keygen" => {
            let k = shop_chain::Identity::generate();
            println!("{{\"seed\":\"{}\",\"public\":\"{}\"}}", hex::encode(k.seed()), k.public_hex());
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&a) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
