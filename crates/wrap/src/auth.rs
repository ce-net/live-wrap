//! `wrap.auth`: the forward-auth in front of every wrapped app. Default deny.
//!
//! A request reaches the app only with a session the issuer signed (in ce: `account-passkey`, after a passkey
//! login) for this app and not yet expired. The session is a one-link capability chain from the issuer key with
//! the right `wrap:<app>`; the user name is in its `tenant` caveat. The app sees only the user header this proxy
//! sets. Any user header the client sent is removed first, and so is the session itself, so the app never sees it.
//!
//! The session may come as `Authorization: Bearer <s>`, as the password of `Authorization: Basic` (so `git push`
//! works), or as the cookie `ce_wrap=<s>`. Each connection carries one request (`Connection: close` both ways).
use base64::Engine;
use shop_chain::{Caveats, Chain, Identity};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub fn right(app: &str) -> String {
    format!("wrap:{app}")
}

/// What the issuer signs at login: `user` may use `app` until `now + ttl_s`.
pub fn issue(issuer: &Identity, app: &str, user: &str, ttl_s: u64) -> String {
    let cav = Caveats { tenant: user.into(), until: shop_chain::now() + ttl_s, ..Default::default() };
    let c = Chain::root(issuer, &format!("user:{user}"), vec![right(app)], cav);
    hex::encode(serde_json::to_vec(&c).expect("chain encodes"))
}

/// The signed-in user, or why not.
pub fn check(issuer_hex: &str, app: &str, token: &str) -> Result<String, String> {
    let bytes = hex::decode(token.trim()).map_err(|_| "session is not hex")?;
    let c: Chain = serde_json::from_slice(&bytes).map_err(|_| "session does not parse")?;
    if c.0.len() != 1 {
        return Err("a session is one link from the issuer".into());
    }
    let v = c.verify(issuer_hex, shop_chain::now()).map_err(|e| e.0)?;
    if !v.allows(&right(app)) {
        return Err(format!("session is not for {app}"));
    }
    let user = v.caveats.tenant;
    if user.is_empty() || user.len() > 64 || !user.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.') {
        return Err("bad user name".into());
    }
    Ok(user)
}

pub struct Gate {
    pub app: String,
    pub issuer_hex: String,
    /// the header the app trusts; empty = forward with no user header (the app has no login of its own)
    pub header: String,
    pub upstream: String,
}

struct Head {
    lines: Vec<String>,
    rest: Vec<u8>,
}

async fn read_head(s: &mut TcpStream) -> Result<Head, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_string();
            let rest = buf[i + 4..].to_vec();
            return Ok(Head { lines: head.split("\r\n").map(String::from).collect(), rest });
        }
        if buf.len() > 64 * 1024 {
            return Err("request head over 64 KiB".into());
        }
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn token_of(lines: &[String]) -> Option<String> {
    for l in lines.iter().skip(1) {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "authorization" {
            if let Some(t) = v.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
            if let Some(b) = v.strip_prefix("Basic ") {
                let d = base64::engine::general_purpose::STANDARD.decode(b.trim()).ok()?;
                let s = String::from_utf8(d).ok()?;
                return s.split_once(':').map(|(_, p)| p.to_string());
            }
        }
        if k == "cookie" {
            for c in v.split(';') {
                if let Some(t) = c.trim().strip_prefix("ce_wrap=") {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

/// The head the app gets: hop and auth headers out, the user header in, one request per connection.
pub fn rewrite(lines: &[String], header: &str, user: &str, peer: &str) -> String {
    let drop = |k: &str| {
        let k = k.to_ascii_lowercase();
        k == "connection" || k == "keep-alive" || k == "proxy-connection" || k == "authorization" || k == "cookie" || k == "x-forwarded-for" || (!header.is_empty() && k == header.to_ascii_lowercase())
    };
    let mut out = vec![lines[0].clone()];
    for l in lines.iter().skip(1) {
        match l.split_once(':') {
            Some((k, v)) if k.trim().eq_ignore_ascii_case("cookie") => {
                let kept: Vec<&str> = v.split(';').map(str::trim).filter(|c| !c.starts_with("ce_wrap=") && !c.is_empty()).collect();
                if !kept.is_empty() {
                    out.push(format!("Cookie: {}", kept.join("; ")));
                }
            }
            Some((k, _)) if drop(k.trim()) => {}
            _ => out.push(l.clone()),
        }
    }
    if !header.is_empty() {
        out.push(format!("{header}: {user}"));
    }
    out.push(format!("X-Forwarded-For: {peer}"));
    out.push("Connection: close".into());
    out.join("\r\n") + "\r\n\r\n"
}

fn deny(why: &str) -> Vec<u8> {
    let body = format!("{{\"denied\":\"{}\"}}\n", why.replace('"', "'"));
    format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"ce passkey\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
}

pub async fn handle(g: Arc<Gate>, mut c: TcpStream) {
    let peer = c.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let Ok(h) = read_head(&mut c).await else { return };
    let line = h.lines.first().cloned().unwrap_or_default();
    let user = match token_of(&h.lines) {
        None => Err("no session".to_string()),
        Some(t) => check(&g.issuer_hex, &g.app, &t),
    };
    let user = match user {
        Ok(u) => u,
        Err(why) => {
            eprintln!("{}", serde_json::json!({ "app": g.app, "req": line, "decision": "deny", "why": why, "at": shop_chain::now() }));
            let _ = c.write_all(&deny(&why)).await;
            return;
        }
    };
    eprintln!("{}", serde_json::json!({ "app": g.app, "req": line, "decision": "allow", "user": user, "at": shop_chain::now() }));
    let Ok(mut up) = TcpStream::connect(&g.upstream).await else {
        let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return;
    };
    let head = rewrite(&h.lines, &g.header, &user, &peer);
    if up.write_all(head.as_bytes()).await.is_err() || up.write_all(&h.rest).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
}

pub async fn serve(g: Gate, bind: &str) -> std::io::Result<()> {
    let l = TcpListener::bind(bind).await?;
    let g = Arc::new(g);
    loop {
        let (s, _) = l.accept().await?;
        tokio::spawn(handle(g.clone(), s));
    }
}
