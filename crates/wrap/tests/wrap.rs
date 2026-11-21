use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use wrap::{auth, catalog, snapshot};

const CAT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");

#[test]
fn all_seven_entries_lint() {
    let all = catalog::all(Path::new(CAT)).unwrap();
    let names: Vec<&str> = all.iter().map(|(_, a)| a.name.as_str()).collect();
    assert_eq!(names, ["code-server", "gitea", "grafana", "home-assistant", "immich", "nextcloud", "ollama"]);
    for (p, a) in &all {
        assert!(catalog::lint(p, a).is_empty(), "{}: {:?}", a.name, catalog::lint(p, a));
    }
}

#[test]
fn lint_refuses_latest_no_passkey_and_secrets() {
    let p = Path::new(CAT).join("gitea.toml");
    let mut a = catalog::load(&p).unwrap();
    a.image = "docker.io/gitea/gitea:latest".into();
    a.auth.passkey = false;
    a.env.insert("ADMIN_PASSWORD".into(), "hunter2".into());
    let e = catalog::lint(&p, &a).join("\n");
    assert!(e.contains("exact tag") && e.contains("passkey must be true") && e.contains("keys cell"), "{e}");
}

#[test]
fn dry_run_for_every_entry_prints_a_capped_container() {
    let bin = env!("CARGO_BIN_EXE_ce-wrap");
    for app in ["code-server", "gitea", "grafana", "home-assistant", "immich", "nextcloud", "ollama"] {
        let o = std::process::Command::new(bin).args(["dry-run", app]).env("WRAP_CATALOG", CAT).output().unwrap();
        assert!(o.status.success(), "{app}: {}", String::from_utf8_lossy(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        let argv: Vec<String> = serde_json::from_value(v["container"].clone()).unwrap();
        assert!(argv.iter().any(|x| x.starts_with("--cpus=")) && argv.iter().any(|x| x.starts_with("--memory=")), "{app}");
        assert!(argv.iter().any(|x| x.starts_with("--publish=127.0.0.1:")), "{app}: the port is on loopback only");
        assert_eq!(v["auth"]["default"], "deny");
    }
}

#[test]
fn sessions_are_checked_for_issuer_app_and_expiry() {
    let iss = shop_chain::Identity::generate();
    let t = auth::issue(&iss, "gitea", "alice", 60);
    assert_eq!(auth::check(&iss.public_hex(), "gitea", &t).unwrap(), "alice");
    assert!(auth::check(&iss.public_hex(), "grafana", &t).unwrap_err().contains("not for grafana"));
    let other = shop_chain::Identity::generate();
    assert!(auth::check(&other.public_hex(), "gitea", &t).is_err());
    assert!(auth::check(&iss.public_hex(), "gitea", "zz").is_err());
}

/// An upstream that answers with the head it received.
fn echo_upstream() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = vec![0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}", head.len());
        }
    });
    a
}

fn get(addr: &str, headers: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "GET /x HTTP/1.1\r\nHost: t\r\n{headers}\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn no_session_is_401_and_a_session_reaches_the_app_with_only_our_user_header() {
    let iss = shop_chain::Identity::generate();
    let up = echo_upstream();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    let g = auth::Gate { app: "gitea".into(), issuer_hex: iss.public_hex(), header: "X-WEBAUTH-USER".into(), upstream: up };
    let a2 = addr.clone();
    std::thread::spawn(move || tokio::runtime::Runtime::new().unwrap().block_on(auth::serve(g, &a2)));
    std::thread::sleep(std::time::Duration::from_millis(300));

    let r = get(&addr, "X-WEBAUTH-USER: admin\r\n");
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    assert!(r.contains("no session"));
    let wrong = auth::issue(&iss, "grafana", "alice", 60);
    assert!(get(&addr, &format!("Authorization: Bearer {wrong}\r\n")).starts_with("HTTP/1.1 401"));
    let forged = auth::issue(&shop_chain::Identity::generate(), "gitea", "admin", 60);
    assert!(get(&addr, &format!("Authorization: Bearer {forged}\r\n")).starts_with("HTTP/1.1 401"));

    let t = auth::issue(&iss, "gitea", "alice", 60);
    let r = get(&addr, &format!("Authorization: Bearer {t}\r\nX-WEBAUTH-USER: admin\r\nCookie: a=1; ce_wrap=zz\r\n"));
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("X-WEBAUTH-USER: alice"), "{r}");
    assert!(!r.contains("admin") && !r.contains(&t) && !r.contains("ce_wrap"), "the client's user header and the session never reach the app: {r}");
    assert!(r.contains("Cookie: a=1"));
}

#[test]
fn restore_refuses_a_tampered_archive_and_a_foreign_seal() {
    let d = std::env::temp_dir().join(format!("wrap-snap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let state = d.join("state");
    std::fs::create_dir_all(state.join("data")).unwrap();
    std::fs::write(state.join("data/repo.txt"), "hello").unwrap();
    let key = shop_chain::Identity::generate();
    let m = snapshot::take("gitea", &state, &["data".into()], &d.join("snaps"), &key).unwrap();

    std::fs::remove_dir_all(&state).unwrap();
    snapshot::restore(&m, &key.public_hex(), "gitea", &state).unwrap();
    assert_eq!(std::fs::read_to_string(state.join("data/repo.txt")).unwrap(), "hello");
    // a non-empty state dir is never overwritten
    assert!(snapshot::restore(&m, &key.public_hex(), "gitea", &state).unwrap_err().contains("not empty"));
    std::fs::remove_dir_all(&state).unwrap();

    assert!(snapshot::restore(&m, &shop_chain::Identity::generate().public_hex(), "gitea", &state).unwrap_err().contains("seal"));
    assert!(snapshot::restore(&m, &key.public_hex(), "grafana", &state).is_err());

    let man: snapshot::Manifest = serde_json::from_slice(&std::fs::read(&m).unwrap()).unwrap();
    let arch = m.parent().unwrap().join(&man.archive);
    let mut b = std::fs::read(&arch).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xff;
    std::fs::write(&arch, b).unwrap();
    let e = snapshot::restore(&m, &key.public_hex(), "gitea", &state).unwrap_err();
    assert!(e.contains("does not match the sealed"), "{e}");
    assert!(!state.join("data/repo.txt").exists());
    let _ = std::fs::remove_dir_all(&d);
}
