//! Login notification: the helper runs a configured command when a terminal
//! is opened from somewhere it has not seen recently, so the account owner
//! hears about a session they did not start.
//!
//! The command is an argv (no shell). `{message}` in any argument is replaced
//! by a one-line description; the same facts are also passed in
//! `TMUXWRAPPER_SESSION`, `TMUXWRAPPER_CLIENT_IP` and
//! `TMUXWRAPPER_CLIENT_COUNTRY`. It runs detached from the request with a
//! time limit, and a failure is only logged: it never blocks or refuses a
//! terminal.

use crate::config::NotifyConfig;
use crate::proto::ClientInfo;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// How long the notification command may run.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Forget everything once this many distinct origins are remembered, so the
/// table cannot grow without bound (the cost is one extra notification).
const MAX_REMEMBERED: usize = 1024;

pub struct Notifier {
    command: Vec<String>,
    quiet: Duration,
    last_seen: Mutex<HashMap<String, Instant>>,
}

/// What two opens must share to count as "the same place": the IPv4 address,
/// or the /64 of an IPv6 address (phones rotate the low bits constantly).
pub(crate) fn origin_key(client: &ClientInfo) -> String {
    match client
        .ip
        .as_deref()
        .and_then(|ip| ip.parse::<IpAddr>().ok())
    {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        None => "unknown".to_string(),
    }
}

/// Record an open from `key` at `now`; true if it should be announced, i.e.
/// `key` was not seen within the last `quiet`.
pub(crate) fn record_open(
    seen: &mut HashMap<String, Instant>,
    key: &str,
    now: Instant,
    quiet: Duration,
) -> bool {
    if seen.len() >= MAX_REMEMBERED && !seen.contains_key(key) {
        seen.clear();
    }
    let recent = seen
        .insert(key.to_string(), now)
        .is_some_and(|last| now.duration_since(last) < quiet);
    !recent
}

pub(crate) fn message(session: &str, client: &ClientInfo) -> String {
    let from = match (&client.ip, &client.country) {
        (Some(ip), Some(country)) => format!("{ip} ({country})"),
        (Some(ip), None) => ip.clone(),
        (None, Some(country)) => format!("an unknown address ({country})"),
        (None, None) => "an unknown address".to_string(),
    };
    format!("Web terminal opened: tmux session '{session}' from {from}")
}

impl Notifier {
    pub fn new(config: &NotifyConfig) -> Self {
        Notifier {
            command: config.command.clone(),
            quiet: Duration::from_secs(config.quiet_secs),
            last_seen: Mutex::new(HashMap::new()),
        }
    }

    /// Call after a terminal was opened. Must run within a tokio runtime.
    pub fn terminal_opened(&self, session: &str, client: &ClientInfo) {
        let key = origin_key(client);
        let announce = {
            let mut seen = self.last_seen.lock().unwrap_or_else(|e| e.into_inner());
            record_open(&mut seen, &key, Instant::now(), self.quiet)
        };
        if !announce {
            return;
        }
        let text = message(session, client);
        let mut cmd = tokio::process::Command::new(&self.command[0]);
        cmd.args(
            self.command[1..]
                .iter()
                .map(|arg| arg.replace("{message}", &text)),
        )
        .env("TMUXWRAPPER_SESSION", session)
        .env("TMUXWRAPPER_CLIENT_IP", client.ip.as_deref().unwrap_or(""))
        .env(
            "TMUXWRAPPER_CLIENT_COUNTRY",
            client.country.as_deref().unwrap_or(""),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
        info!(origin = %key, "sending login notification");
        tokio::spawn(async move {
            match tokio::time::timeout(COMMAND_TIMEOUT, cmd.output()).await {
                Ok(Ok(out)) if out.status.success() => {}
                Ok(Ok(out)) => warn!(
                    status = %out.status,
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "login notification command failed"
                ),
                Ok(Err(e)) => warn!(error = %e, "could not run the login notification command"),
                Err(_) => warn!("login notification command timed out"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(ip: Option<&str>, country: Option<&str>) -> ClientInfo {
        ClientInfo {
            ip: ip.map(str::to_string),
            country: country.map(str::to_string),
        }
    }

    #[test]
    fn first_open_is_announced_and_repeats_within_the_quiet_period_are_not() {
        let mut seen = HashMap::new();
        let quiet = Duration::from_secs(3600);
        let t0 = Instant::now();
        assert!(record_open(&mut seen, "1.2.3.4", t0, quiet));
        assert!(!record_open(
            &mut seen,
            "1.2.3.4",
            t0 + Duration::from_secs(60),
            quiet
        ));
        // A different origin is announced straight away.
        assert!(record_open(
            &mut seen,
            "5.6.7.8",
            t0 + Duration::from_secs(61),
            quiet
        ));
    }

    #[test]
    fn the_quiet_period_runs_from_the_last_open() {
        let mut seen = HashMap::new();
        let quiet = Duration::from_secs(3600);
        let t0 = Instant::now();
        assert!(record_open(&mut seen, "k", t0, quiet));
        assert!(!record_open(
            &mut seen,
            "k",
            t0 + Duration::from_secs(3000),
            quiet
        ));
        // 3000 s after the previous open, 6000 s after the first: still quiet.
        assert!(!record_open(
            &mut seen,
            "k",
            t0 + Duration::from_secs(6000),
            quiet
        ));
        assert!(record_open(
            &mut seen,
            "k",
            t0 + Duration::from_secs(9600),
            quiet
        ));
    }

    #[test]
    fn zero_quiet_announces_every_open() {
        let mut seen = HashMap::new();
        let t0 = Instant::now();
        assert!(record_open(&mut seen, "k", t0, Duration::ZERO));
        assert!(record_open(&mut seen, "k", t0, Duration::ZERO));
    }

    #[test]
    fn the_table_is_bounded() {
        let mut seen = HashMap::new();
        let quiet = Duration::from_secs(3600);
        let t0 = Instant::now();
        for i in 0..MAX_REMEMBERED {
            assert!(record_open(&mut seen, &format!("k{i}"), t0, quiet));
        }
        assert!(record_open(&mut seen, "one-more", t0, quiet));
        assert!(seen.len() <= MAX_REMEMBERED);
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_key() {
        let a = origin_key(&client(Some("2001:db8:1:2:aaaa::1"), None));
        let b = origin_key(&client(Some("2001:db8:1:2:bbbb::9"), None));
        let other = origin_key(&client(Some("2001:db8:1:3::1"), None));
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:1:2::/64");
        assert_ne!(a, other);
        assert_eq!(
            origin_key(&client(Some("203.0.113.7"), None)),
            "203.0.113.7"
        );
        assert_eq!(origin_key(&client(None, Some("CA"))), "unknown");
    }

    #[test]
    fn message_names_session_address_and_country() {
        assert_eq!(
            message("main", &client(Some("203.0.113.7"), Some("CA"))),
            "Web terminal opened: tmux session 'main' from 203.0.113.7 (CA)"
        );
        assert_eq!(
            message("main", &client(None, None)),
            "Web terminal opened: tmux session 'main' from an unknown address"
        );
    }
}
