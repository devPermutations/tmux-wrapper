//! Black-box end-to-end checks against a real, privilege-separated tmuxwrapper
//! running under a transient systemd unit. Driven by `scripts/e2e-privsep.sh`;
//! every test is `#[ignore]` because it needs that environment.
//!
//! Env: `E2E_KEY_PEM` (private key PEM path), `E2E_URL` (host:port),
//! `E2E_UNIT` (systemd unit name, without `.service`).

use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const EMAIL: &str = "e2e@example.com";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} not set"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mint(email: &str, exp: u64) -> String {
    let pem = std::fs::read(env("E2E_KEY_PEM")).expect("read key pem");
    let key = EncodingKey::from_rsa_pem(&pem).expect("parse key pem");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("e2e".into());
    let claims = json!({
        "email": email,
        "sub": "e2e-sub",
        "aud": "e2e-aud",
        "iss": "https://e2e.cloudflareaccess.com",
        "exp": exp,
    });
    encode(&header, &claims, &key).expect("mint token")
}

fn good_token() -> String {
    mint(EMAIL, now() + 600)
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(session: &str, token: &str) -> Ws {
    let url = format!("ws://{}/ws?session={session}", env("E2E_URL"));
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("Cf-Access-Jwt-Assertion", token.parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("websocket connect");
    ws
}

/// Read binary frames until `needle` shows up in the 0x00 (terminal data)
/// stream, or `secs` elapse.
async fn expect_output(ws: &mut Ws, needle: &str, secs: u64) {
    let mut seen = String::new();
    let res = timeout(Duration::from_secs(secs), async {
        while let Some(msg) = ws.next().await {
            match msg.expect("ws error") {
                Message::Binary(b) if b.first() == Some(&0) => {
                    seen.push_str(&String::from_utf8_lossy(&b[1..]));
                    if seen.contains(needle) {
                        return;
                    }
                }
                Message::Close(c) => panic!("socket closed early: {c:?}; output so far: {seen:?}"),
                _ => {}
            }
        }
        panic!("socket ended; output so far: {seen:?}");
    })
    .await;
    assert!(
        res.is_ok(),
        "timed out waiting for {needle:?}; saw {seen:?}"
    );
}

async fn send_line(ws: &mut Ws, line: &str) {
    let mut data = vec![0u8];
    data.extend_from_slice(line.as_bytes());
    ws.send(Message::Binary(data.into())).await.unwrap();
}

/// Open `e2e-a` (creating the tmux session), prove the shell answers, close.
async fn ensure_session_a() {
    let mut ws = ws_connect("e2e-a", &good_token()).await;
    send_line(&mut ws, "echo ready-$((40+2))\r").await;
    expect_output(&mut ws, "ready-42", 5).await;
    let _ = ws.close(None).await;
}

fn http_url(path: &str) -> String {
    format!("http://{}{path}", env("E2E_URL"))
}

fn cmd_out(prog: &str, args: &[&str]) -> String {
    let out = Command::new(prog).args(args).output().expect("spawn");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn main_pid() -> u32 {
    let unit = format!("{}.service", env("E2E_UNIT"));
    let pid: u32 = cmd_out("systemctl", &["show", "-p", "MainPID", "--value", &unit])
        .parse()
        .expect("MainPID");
    assert!(pid > 0, "unit {unit} has no main pid");
    pid
}

fn status_field(pid: u32, field: &str) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix(&format!("{field}:")))
        .map(|v| v.trim().to_string())
}

/// All ids on a `Uid:` / `Gid:` line: real, effective, saved, filesystem.
fn ids(pid: u32, field: &str) -> Vec<u32> {
    status_field(pid, field)
        .unwrap_or_else(|| panic!("no {field} for pid {pid}"))
        .split_whitespace()
        .map(|v| v.parse().expect("numeric id"))
        .collect()
}

fn assert_ids(pid: u32, field: &str, want: u32, who: &str) {
    assert_eq!(
        ids(pid, field),
        vec![want; 4],
        "{who}: every {field} field (real, effective, saved, fs) must be {want}"
    );
}

fn assert_no_caps(pid: u32, who: &str) {
    for field in ["CapPrm", "CapEff"] {
        let cap = status_field(pid, field).unwrap_or_else(|| panic!("no {field}"));
        assert_eq!(
            u64::from_str_radix(&cap, 16).unwrap(),
            0,
            "{who}: {field} must be 0"
        );
    }
}

/// Every process whose parent is in `parents`, with its `State:` line. Scans
/// /proc rather than cgroup.procs: the kernel leaves zombies out of the latter.
fn children_of(parents: &[u32]) -> Vec<(u32, u32, String)> {
    std::fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let ppid: u32 = status_field(pid, "PPid")?.parse().ok()?;
            let state = status_field(pid, "State")?;
            parents.contains(&ppid).then_some((pid, ppid, state))
        })
        .collect()
}

fn cgroup_pids() -> Vec<u32> {
    let path = format!(
        "/sys/fs/cgroup/system.slice/{}.service/cgroup.procs",
        env("E2E_UNIT")
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn helper_pid(main: u32) -> u32 {
    let kids = cmd_out("pgrep", &["-P", &main.to_string()]);
    kids.lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .find(|p| {
            std::fs::read_to_string(format!("/proc/{p}/comm"))
                .map(|c| c.trim() == "tmuxwrapper")
                .unwrap_or(false)
        })
        .expect("no helper child of the main process")
}

fn id_of(flag: &str, user: &str) -> u32 {
    cmd_out("id", &[flag, user]).parse().expect("id output")
}

#[tokio::test]
#[ignore]
async fn process_model() {
    // Keep a terminal open so tmux processes exist while we inspect the cgroup.
    let mut ws = ws_connect("e2e-a", &good_token()).await;
    send_line(&mut ws, "echo up-$((1+1))\r").await;
    expect_output(&mut ws, "up-2", 5).await;

    let main = main_pid();
    assert_ids(main, "Uid", id_of("-u", "nobody"), "front");
    assert_ids(main, "Gid", id_of("-g", "nobody"), "front");
    assert_eq!(
        status_field(main, "Groups").as_deref(),
        Some(""),
        "front must have no supplementary groups"
    );
    assert_no_caps(main, "front");

    let helper = helper_pid(main);
    let gid = id_of("-g", "ktulu");
    assert_ids(helper, "Uid", id_of("-u", "ktulu"), "helper");
    assert_ids(helper, "Gid", gid, "helper");
    assert_eq!(
        status_field(helper, "Groups").as_deref(),
        Some(gid.to_string().as_str()),
        "helper must carry only the primary gid"
    );
    assert_no_caps(helper, "helper");

    let cgroup = cgroup_pids();
    assert!(
        cgroup.contains(&main) && cgroup.contains(&helper),
        "cgroup scan {cgroup:?} must contain main {main} and helper {helper}"
    );
    for pid in cgroup {
        if let Some(uid) = status_field(pid, "Uid") {
            assert!(
                uid.split_whitespace().all(|id| id != "0"),
                "pid {pid} in the unit's cgroup has a root uid: {uid}"
            );
        }
    }
    let _ = ws.close(None).await;
}

#[tokio::test]
#[ignore]
async fn terminal_echo() {
    let mut ws = ws_connect("e2e-a", &good_token()).await;
    // The typed text never contains the expanded result, only the output does.
    send_line(&mut ws, "echo e2e-$((7000+343))x\r").await;
    expect_output(&mut ws, "e2e-7343x", 5).await;
    let _ = ws.close(None).await;
}

#[tokio::test]
#[ignore]
async fn sessions_list_and_delete() {
    ensure_session_a().await;
    let http = reqwest::Client::new();
    let tok = good_token();

    let r = http
        .get(http_url("/api/sessions"))
        .header("Cf-Access-Jwt-Assertion", &tok)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body.as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "e2e-a"),
        "e2e-a not listed: {body}"
    );

    let del = |t: String| {
        let http = http.clone();
        async move {
            http.delete(http_url("/api/sessions/e2e-a"))
                .header("Cf-Access-Jwt-Assertion", t)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(del(tok.clone()).await, 200);
    assert_eq!(del(tok).await, 404);
}

#[tokio::test]
#[ignore]
async fn bad_tokens_rejected_at_front() {
    let http = reqwest::Client::new();
    let get = |t: String| {
        let http = http.clone();
        async move {
            http.get(http_url("/api/sessions"))
                .header("Cf-Access-Jwt-Assertion", t)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(get(mint("stranger@example.com", now() + 600)).await, 403);
    assert_eq!(get(mint(EMAIL, now() - 300)).await, 401);
}

#[tokio::test]
#[ignore]
async fn socket_closes_4001_when_token_expires() {
    // jsonwebtoken allows 60 s leeway, so a near-future exp passes the upgrade.
    let mut ws = ws_connect("e2e-exp", &mint(EMAIL, now() + 5)).await;
    let code = timeout(Duration::from_secs(10), async {
        while let Some(msg) = ws.next().await {
            if let Ok(Message::Close(Some(f))) = msg {
                return Some(u16::from(f.code));
            }
        }
        None
    })
    .await
    .expect("no close within 10 s of expiry");
    assert_eq!(code, Some(4001));
}

#[tokio::test]
#[ignore]
async fn no_zombies_after_sockets_close() {
    let main = main_pid();
    let helper = helper_pid(main);

    // With a terminal open the scan must see the helper's tmux client, so
    // the check below cannot pass by finding nothing.
    let mut ws = ws_connect("e2e-a", &good_token()).await;
    send_line(&mut ws, "echo open-$((2+3))\r").await;
    expect_output(&mut ws, "open-5", 5).await;
    let open = children_of(&[helper]);
    assert!(
        !open.is_empty(),
        "no child of helper {helper} found while a terminal is open"
    );
    let _ = ws.close(None).await;
    ensure_session_a().await;
    sleep(Duration::from_secs(3)).await;

    let mut parents = cgroup_pids();
    parents.extend([main, helper]);
    let zombies: Vec<_> = children_of(&parents)
        .into_iter()
        .filter(|(_, _, state)| state.starts_with('Z'))
        .collect();
    assert!(
        zombies.is_empty(),
        "zombies (pid, ppid, state) after sockets closed: {zombies:?}"
    );
}
