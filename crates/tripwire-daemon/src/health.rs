//! Listener liveness and metrics (SECURITY.md T3).
//!
//! The failure this exists to prevent: the daemon stalls (RPC outage, a hung
//! call, a stale endpoint) and the system silently reverts to human-mediated
//! response while every dashboard still says "nothing found". "Tripwire is
//! down" must never look like "Tripwire looked and found nothing".
//!
//! Everything here is pure state with an injected clock (`now`, unix
//! seconds), so the behaviour is unit-tested without sleeping. The pieces:
//!
//! * [`Health`] — counters plus the timestamps that define liveness.
//! * [`Status`] — healthy, or unhealthy with a specific, actionable reason.
//! * [`Watchdog`] — turns status *transitions* into [`Alert`]s (and periodic
//!   reminders), and is driven from a task independent of the detection loop
//!   so that a hung tick is still noticed.
//! * [`serve`] — a minimal HTTP endpoint: `/healthz`, `/metrics`
//!   (Prometheus text), `/status` (JSON).

use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// No successful tick for this long means the listener is stalled.
    pub stale_after: Duration,
    /// The chain head has not advanced for this long: the RPC is serving
    /// stale data, or the chain has halted. Both mean the listener cannot
    /// see new blocks, which is what it exists to do.
    pub chain_stall_after: Duration,
    /// Consecutive failed ticks that mark the listener unhealthy even
    /// before `stale_after` elapses.
    pub max_consecutive_failures: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            stale_after: Duration::from_secs(30),
            chain_stall_after: Duration::from_secs(300),
            max_consecutive_failures: 5,
        }
    }
}

/// Why the listener is not healthy. Each variant names something an
/// operator can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unhealthy {
    /// Never completed a tick, and startup grace has passed.
    NeverTicked { since_start_secs: u64 },
    /// No successful tick for `age_secs` (hung or persistently failing).
    Stalled { age_secs: u64 },
    /// Ticks keep failing.
    Failing {
        consecutive: u32,
        last_error: String,
    },
    /// Ticks succeed but the head has not moved for `age_secs`.
    ChainNotAdvancing { age_secs: u64 },
    /// The last tick decided to pause and the pause transaction failed.
    /// The most urgent state: an exploit was detected and not contained.
    PauseFailing { errors: usize },
}

impl Unhealthy {
    pub fn kind(&self) -> &'static str {
        match self {
            Unhealthy::NeverTicked { .. } => "never_ticked",
            Unhealthy::Stalled { .. } => "stalled",
            Unhealthy::Failing { .. } => "failing",
            Unhealthy::ChainNotAdvancing { .. } => "chain_not_advancing",
            Unhealthy::PauseFailing { .. } => "pause_failing",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Unhealthy::NeverTicked { since_start_secs } => {
                format!("no successful tick since start ({since_start_secs}s ago)")
            }
            Unhealthy::Stalled { age_secs } => {
                format!("no successful tick for {age_secs}s: the listener is not evaluating blocks")
            }
            Unhealthy::Failing {
                consecutive,
                last_error,
            } => format!("{consecutive} consecutive failed ticks; last error: {last_error}"),
            Unhealthy::ChainNotAdvancing { age_secs } => format!(
                "chain head has not advanced for {age_secs}s: the RPC is stale or the chain halted"
            ),
            Unhealthy::PauseFailing { errors } => format!(
                "{errors} pause transaction(s) failed on the last tick: a detected exploit may not be contained"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Healthy,
    Unhealthy(Unhealthy),
}

impl Status {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Status::Healthy)
    }
}

/// What one tick produced, as far as liveness is concerned.
#[derive(Debug, Clone, Default)]
pub struct TickOutcome {
    pub head: u64,
    pub blocks_processed: u64,
    pub pauses: usize,
    pub pause_errors: usize,
    pub reorged: bool,
}

#[derive(Debug, Default)]
struct Inner {
    started_unix: u64,
    last_ok_unix: Option<u64>,
    head: u64,
    head_changed_unix: Option<u64>,
    consecutive_failures: u32,
    last_error: String,
    last_pause_errors: usize,
    ticks: u64,
    tick_failures: u64,
    tick_timeouts: u64,
    blocks: u64,
    pauses: u64,
    pause_errors: u64,
    reorgs: u64,
}

pub struct Health {
    cfg: HealthConfig,
    inner: Mutex<Inner>,
}

impl Health {
    pub fn new(cfg: HealthConfig, now: u64) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                started_unix: now,
                ..Default::default()
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means another thread panicked mid-update of
        // plain counters; the data is still usable and liveness reporting
        // must not itself become a source of failure.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn record_ok(&self, now: u64, o: &TickOutcome) {
        let mut i = self.lock();
        i.ticks += 1;
        i.last_ok_unix = Some(now);
        i.consecutive_failures = 0;
        if o.head != i.head || i.head_changed_unix.is_none() {
            i.head = o.head;
            i.head_changed_unix = Some(now);
        }
        i.blocks += o.blocks_processed;
        i.pauses += o.pauses as u64;
        i.pause_errors += o.pause_errors as u64;
        i.last_pause_errors = o.pause_errors;
        if o.reorged {
            i.reorgs += 1;
        }
    }

    pub fn record_err(&self, msg: &str) {
        let mut i = self.lock();
        i.ticks += 1;
        i.tick_failures += 1;
        i.consecutive_failures += 1;
        i.last_error = msg.chars().take(300).collect();
    }

    pub fn record_timeout(&self) {
        let mut i = self.lock();
        i.tick_timeouts += 1;
        drop(i);
        self.record_err("tick timed out");
    }

    pub fn status(&self, now: u64) -> Status {
        let i = self.lock();
        // Most urgent first.
        if i.last_pause_errors > 0 {
            return Status::Unhealthy(Unhealthy::PauseFailing {
                errors: i.last_pause_errors,
            });
        }
        match i.last_ok_unix {
            None => {
                let since = now.saturating_sub(i.started_unix);
                if since > self.cfg.stale_after.as_secs() {
                    return Status::Unhealthy(Unhealthy::NeverTicked {
                        since_start_secs: since,
                    });
                }
                return Status::Healthy; // still in startup grace
            }
            Some(ok) => {
                let age = now.saturating_sub(ok);
                if age > self.cfg.stale_after.as_secs() {
                    return Status::Unhealthy(Unhealthy::Stalled { age_secs: age });
                }
            }
        }
        if i.consecutive_failures >= self.cfg.max_consecutive_failures {
            return Status::Unhealthy(Unhealthy::Failing {
                consecutive: i.consecutive_failures,
                last_error: i.last_error.clone(),
            });
        }
        if let Some(changed) = i.head_changed_unix {
            let age = now.saturating_sub(changed);
            if age > self.cfg.chain_stall_after.as_secs() {
                return Status::Unhealthy(Unhealthy::ChainNotAdvancing { age_secs: age });
            }
        }
        Status::Healthy
    }

    /// Prometheus text exposition format.
    pub fn render_prometheus(&self, now: u64) -> String {
        let status = self.status(now);
        let i = self.lock();
        let mut out = String::new();
        let mut metric = |name: &str, kind: &str, help: &str, value: String| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}"
            );
        };
        metric(
            "tripwire_healthy",
            "gauge",
            "1 if the listener is healthy, 0 otherwise (see /status for why).",
            (status.is_healthy() as u8).to_string(),
        );
        metric(
            "tripwire_last_successful_tick_timestamp_seconds",
            "gauge",
            "Unix time of the last successful tick; 0 if none yet.",
            i.last_ok_unix.unwrap_or(0).to_string(),
        );
        metric(
            "tripwire_seconds_since_last_successful_tick",
            "gauge",
            "Age of the last successful tick; the alerting signal for a stalled listener.",
            i.last_ok_unix
                .map(|t| now.saturating_sub(t))
                .unwrap_or_else(|| now.saturating_sub(i.started_unix))
                .to_string(),
        );
        metric(
            "tripwire_head_block",
            "gauge",
            "Latest chain head seen.",
            i.head.to_string(),
        );
        metric(
            "tripwire_seconds_since_head_advanced",
            "gauge",
            "Seconds since the chain head last changed.",
            i.head_changed_unix
                .map(|t| now.saturating_sub(t))
                .unwrap_or(0)
                .to_string(),
        );
        metric(
            "tripwire_consecutive_tick_failures",
            "gauge",
            "Failed ticks in a row.",
            i.consecutive_failures.to_string(),
        );
        for (name, help, v) in [
            ("tripwire_ticks_total", "Ticks attempted.", i.ticks),
            (
                "tripwire_tick_failures_total",
                "Ticks that returned an error or timed out.",
                i.tick_failures,
            ),
            (
                "tripwire_tick_timeouts_total",
                "Ticks cancelled by the tick timeout.",
                i.tick_timeouts,
            ),
            (
                "tripwire_blocks_processed_total",
                "Blocks evaluated.",
                i.blocks,
            ),
            ("tripwire_pauses_total", "Pauses submitted.", i.pauses),
            (
                "tripwire_pause_errors_total",
                "Pause attempts that failed.",
                i.pause_errors,
            ),
            ("tripwire_reorgs_total", "Reorgs observed.", i.reorgs),
        ] {
            metric(name, "counter", help, v.to_string());
        }
        out
    }

    /// Small hand-written JSON (no serde dependency needed for this).
    pub fn render_json(&self, now: u64) -> String {
        let status = self.status(now);
        let i = self.lock();
        let (healthy, kind, msg) = match &status {
            Status::Healthy => (true, "healthy", String::new()),
            Status::Unhealthy(u) => (false, u.kind(), u.message()),
        };
        format!(
            "{{\"healthy\":{healthy},\"state\":\"{kind}\",\"message\":\"{}\",\"head\":{},\"ticks\":{},\"tick_failures\":{},\"pauses\":{},\"pause_errors\":{},\"last_successful_tick\":{},\"unix_now\":{now}}}",
            json_escape(&msg),
            i.head,
            i.ticks,
            i.tick_failures,
            i.pauses,
            i.pause_errors,
            i.last_ok_unix.map(|t| t.to_string()).unwrap_or("null".into()),
        )
    }
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

// ---------------------------------------------------------------- alerting

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub severity: Severity,
    pub kind: String,
    pub message: String,
    pub unix: u64,
}

impl Alert {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"severity\":\"{}\",\"kind\":\"{}\",\"message\":\"{}\",\"unix\":{},\"text\":\"[tripwire {}] {}\"}}",
            match self.severity {
                Severity::Info => "info",
                Severity::Critical => "critical",
            },
            json_escape(&self.kind),
            json_escape(&self.message),
            self.unix,
            match self.severity {
                Severity::Info => "info",
                Severity::Critical => "CRITICAL",
            },
            json_escape(&self.message),
        )
    }
}

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, alert: &Alert);
}

/// Always-on fallback: the alert reaches the logs even with no webhook.
pub struct LogNotifier;

#[async_trait]
impl Notifier for LogNotifier {
    async fn notify(&self, a: &Alert) {
        match a.severity {
            Severity::Critical => {
                tracing::error!(kind = %a.kind, "ALERT: {}", a.message)
            }
            Severity::Info => tracing::info!(kind = %a.kind, "alert: {}", a.message),
        }
    }
}

/// POSTs each alert as JSON (`text` is Slack/Discord-compatible) with a
/// short timeout and a few retries. A failing webhook must never take the
/// daemon down, so failures are logged and swallowed.
pub struct WebhookNotifier {
    url: String,
    client: reqwest::Client,
}

impl WebhookNotifier {
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { url, client }
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    async fn notify(&self, a: &Alert) {
        let body = a.to_json();
        for attempt in 1..=3u32 {
            let r = self
                .client
                .post(&self.url)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await;
            match r {
                Ok(resp) if resp.status().is_success() => return,
                Ok(resp) => {
                    tracing::warn!(attempt, status = %resp.status(), "alert webhook rejected")
                }
                Err(e) => tracing::warn!(attempt, error = %e, "alert webhook failed"),
            }
            tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
        }
        tracing::error!("alert webhook unreachable after retries; alert only in logs");
    }
}

/// Turns status observations into alerts: one on becoming unhealthy, one on
/// recovery, a reminder while it stays unhealthy, and an immediate new alert
/// if the *reason* changes (e.g. stalled -> pause failing).
pub struct Watchdog {
    reminder_every: u64,
    last: Option<Unhealthy>,
    last_alert_unix: u64,
}

impl Watchdog {
    pub fn new(reminder_every: Duration) -> Self {
        Self {
            reminder_every: reminder_every.as_secs(),
            last: None,
            last_alert_unix: 0,
        }
    }

    pub fn observe(&mut self, status: &Status, now: u64) -> Option<Alert> {
        match (&self.last, status) {
            (None, Status::Healthy) => None,
            (Some(_), Status::Healthy) => {
                self.last = None;
                Some(Alert {
                    severity: Severity::Info,
                    kind: "recovered".into(),
                    message: "listener recovered and is healthy again".into(),
                    unix: now,
                })
            }
            (prev, Status::Unhealthy(u)) => {
                let changed_reason = prev.as_ref().map(|p| p.kind()) != Some(u.kind());
                let due = now.saturating_sub(self.last_alert_unix) >= self.reminder_every;
                if prev.is_none() || changed_reason || due {
                    let reminder = prev.is_some() && !changed_reason;
                    self.last = Some(u.clone());
                    self.last_alert_unix = now;
                    Some(Alert {
                        severity: Severity::Critical,
                        kind: u.kind().into(),
                        message: if reminder {
                            format!("still unhealthy: {}", u.message())
                        } else {
                            u.message()
                        },
                        unix: now,
                    })
                } else {
                    self.last = Some(u.clone());
                    None
                }
            }
        }
    }
}

// ------------------------------------------------------------------ server

/// Serves `/healthz`, `/metrics` and `/status` until the task is dropped.
/// Deliberately tiny and dependency-free: it answers three GETs and closes.
/// Binds where told (default loopback in the daemon) and reads only the
/// request line, with a short deadline, so a slow or hostile client cannot
/// hold it up.
pub async fn serve(addr: &str, health: std::sync::Arc<Health>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "health/metrics endpoint listening");
    serve_listener(listener, health).await
}

/// As [`serve`], on an already-bound listener (so tests can use port 0).
pub async fn serve_listener(
    listener: tokio::net::TcpListener,
    health: std::sync::Arc<Health>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let (mut sock, _) = listener.accept().await?;
        let health = health.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let line = req.lines().next().unwrap_or("");
            let mut parts = line.split_whitespace();
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let now = unix_now();
            let (code, ctype, body) = if method != "GET" {
                (
                    "405 Method Not Allowed",
                    "text/plain",
                    "method not allowed\n".to_string(),
                )
            } else {
                match path {
                    "/healthz" => match health.status(now) {
                        Status::Healthy => ("200 OK", "text/plain", "ok\n".to_string()),
                        Status::Unhealthy(u) => (
                            "503 Service Unavailable",
                            "text/plain",
                            format!("{}: {}\n", u.kind(), u.message()),
                        ),
                    },
                    "/metrics" => (
                        "200 OK",
                        "text/plain; version=0.0.4",
                        health.render_prometheus(now),
                    ),
                    "/status" => ("200 OK", "application/json", health.render_json(now)),
                    _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
                }
            };
            let resp = format!(
                "HTTP/1.1 {code}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h() -> Health {
        Health::new(HealthConfig::default(), 1_000)
    }

    fn ok(head: u64) -> TickOutcome {
        TickOutcome {
            head,
            blocks_processed: 1,
            ..Default::default()
        }
    }

    #[test]
    fn a_fresh_daemon_is_healthy_only_during_the_startup_grace() {
        let h = h();
        assert!(h.status(1_010).is_healthy());
        assert!(matches!(
            h.status(1_100),
            Status::Unhealthy(Unhealthy::NeverTicked { .. })
        ));
    }

    #[test]
    fn regular_ticks_with_an_advancing_head_are_healthy() {
        let h = h();
        for t in 0..10u64 {
            h.record_ok(1_000 + t * 12, &ok(100 + t));
        }
        assert!(h.status(1_000 + 9 * 12 + 5).is_healthy());
    }

    #[test]
    fn a_hung_listener_is_reported_stalled_even_with_no_failures() {
        // The detection loop can block forever on an RPC call and never
        // record an error; only elapsed time reveals it.
        let h = h();
        h.record_ok(1_000, &ok(1));
        assert!(h.status(1_020).is_healthy());
        assert_eq!(
            h.status(1_031),
            Status::Unhealthy(Unhealthy::Stalled { age_secs: 31 })
        );
    }

    #[test]
    fn repeated_failures_are_unhealthy_before_the_stale_window() {
        let h = h();
        h.record_ok(1_000, &ok(1));
        for _ in 0..5 {
            h.record_err("rpc down");
        }
        match h.status(1_002) {
            Status::Unhealthy(Unhealthy::Failing {
                consecutive,
                last_error,
            }) => {
                assert_eq!(consecutive, 5);
                assert_eq!(last_error, "rpc down");
            }
            s => panic!("{s:?}"),
        }
        // One good tick clears it.
        h.record_ok(1_003, &ok(2));
        assert!(h.status(1_004).is_healthy());
    }

    #[test]
    fn a_stale_rpc_that_serves_the_same_head_is_detected() {
        // Ticks succeed, but the endpoint keeps returning the same head:
        // exactly what an eclipsed or lagging RPC looks like.
        let h = h();
        for t in 0..40u64 {
            h.record_ok(1_000 + t * 10, &ok(500));
        }
        assert!(matches!(
            h.status(1_000 + 39 * 10 + 1),
            Status::Unhealthy(Unhealthy::ChainNotAdvancing { .. })
        ));
    }

    #[test]
    fn a_failed_pause_is_the_most_urgent_state_and_clears_when_resolved() {
        let h = h();
        h.record_ok(
            1_000,
            &TickOutcome {
                head: 9,
                pause_errors: 1,
                ..Default::default()
            },
        );
        assert_eq!(
            h.status(1_001),
            Status::Unhealthy(Unhealthy::PauseFailing { errors: 1 })
        );
        h.record_ok(1_002, &ok(10));
        assert!(h.status(1_003).is_healthy());
    }

    #[test]
    fn timeouts_count_as_failures_and_are_exported() {
        let h = h();
        h.record_ok(1_000, &ok(1));
        h.record_timeout();
        let m = h.render_prometheus(1_001);
        assert!(m.contains("tripwire_tick_timeouts_total 1"), "{m}");
        assert!(m.contains("tripwire_tick_failures_total 1"), "{m}");
        assert!(m.contains("tripwire_consecutive_tick_failures 1"), "{m}");
    }

    #[test]
    fn prometheus_output_is_well_formed() {
        let h = h();
        h.record_ok(
            1_000,
            &TickOutcome {
                head: 42,
                blocks_processed: 3,
                pauses: 1,
                reorged: true,
                ..Default::default()
            },
        );
        let m = h.render_prometheus(1_005);
        for needle in [
            "tripwire_healthy 1",
            "tripwire_head_block 42",
            "tripwire_blocks_processed_total 3",
            "tripwire_pauses_total 1",
            "tripwire_reorgs_total 1",
            "tripwire_seconds_since_last_successful_tick 5",
        ] {
            assert!(m.contains(needle), "missing `{needle}` in:\n{m}");
        }
        // Every sample has HELP and TYPE lines.
        assert_eq!(m.matches("# HELP").count(), m.matches("# TYPE").count());
    }

    #[test]
    fn json_status_escapes_error_text() {
        let h = h();
        h.record_ok(1_000, &ok(1));
        for _ in 0..5 {
            h.record_err("bad \"quote\"\nnewline \\ slash");
        }
        let j = h.render_json(1_001);
        assert!(j.contains("\\\"quote\\\""), "{j}");
        assert!(j.contains("\\n"), "{j}");
        assert!(j.contains("\"healthy\":false"), "{j}");
    }

    // --- watchdog

    #[test]
    fn watchdog_alerts_once_on_failure_then_reminds_then_reports_recovery() {
        let mut w = Watchdog::new(Duration::from_secs(600));
        let bad = Status::Unhealthy(Unhealthy::Stalled { age_secs: 40 });
        assert!(w.observe(&Status::Healthy, 100).is_none());

        let a = w.observe(&bad, 200).expect("first failure alerts");
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.kind, "stalled");

        // No spam while it stays unhealthy...
        assert!(w.observe(&bad, 210).is_none());
        assert!(w.observe(&bad, 700).is_none());
        // ...but a reminder once the interval passes.
        let r = w.observe(&bad, 800).expect("reminder");
        assert!(r.message.starts_with("still unhealthy"), "{}", r.message);

        let rec = w.observe(&Status::Healthy, 900).expect("recovery");
        assert_eq!(rec.severity, Severity::Info);
        assert!(w.observe(&Status::Healthy, 910).is_none());
    }

    #[test]
    fn watchdog_re_alerts_immediately_when_the_reason_gets_worse() {
        let mut w = Watchdog::new(Duration::from_secs(600));
        w.observe(&Status::Unhealthy(Unhealthy::Stalled { age_secs: 40 }), 100)
            .unwrap();
        let a = w
            .observe(
                &Status::Unhealthy(Unhealthy::PauseFailing { errors: 1 }),
                105,
            )
            .expect("a failed pause must not wait for the reminder interval");
        assert_eq!(a.kind, "pause_failing");
    }

    #[test]
    fn alert_json_is_escaped_and_carries_slack_style_text() {
        let a = Alert {
            severity: Severity::Critical,
            kind: "failing".into(),
            message: "boom \"x\"".into(),
            unix: 5,
        };
        let j = a.to_json();
        assert!(j.contains("\"severity\":\"critical\""), "{j}");
        assert!(j.contains("boom \\\"x\\\""), "{j}");
        assert!(j.contains("[tripwire CRITICAL]"), "{j}");
    }

    // --- real sockets

    async fn get(addr: std::net::SocketAddr, path: &str, method: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(format!("{method} {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        out
    }

    async fn spawn_server(h: std::sync::Arc<Health>) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_listener(l, h));
        addr
    }

    #[tokio::test]
    async fn the_endpoint_serves_health_metrics_and_status_and_rejects_the_rest() {
        let h = std::sync::Arc::new(Health::new(HealthConfig::default(), unix_now()));
        h.record_ok(unix_now(), &ok(7));
        let addr = spawn_server(h.clone()).await;

        let r = get(addr, "/healthz", "GET").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.ends_with("ok\n"), "{r}");

        let r = get(addr, "/metrics", "GET").await;
        assert!(r.contains("tripwire_head_block 7"), "{r}");

        let r = get(addr, "/status", "GET").await;
        assert!(
            r.contains("application/json") && r.contains("\"healthy\":true"),
            "{r}"
        );

        assert!(get(addr, "/nope", "GET").await.starts_with("HTTP/1.1 404"));
        assert!(get(addr, "/healthz", "POST")
            .await
            .starts_with("HTTP/1.1 405"));

        // Unhealthy => 503 with the reason, so a load balancer or k8s probe
        // can act on it.
        for _ in 0..5 {
            h.record_err("rpc down");
        }
        let r = get(addr, "/healthz", "GET").await;
        assert!(r.starts_with("HTTP/1.1 503"), "{r}");
        assert!(r.contains("failing") && r.contains("rpc down"), "{r}");
    }

    #[tokio::test]
    async fn a_silent_client_cannot_wedge_the_endpoint() {
        let h = std::sync::Arc::new(Health::new(HealthConfig::default(), unix_now()));
        let addr = spawn_server(h).await;
        // Connect and say nothing; other requests must still be served.
        let _idle = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r = get(addr, "/healthz", "GET").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }

    #[tokio::test]
    async fn the_webhook_notifier_posts_json_and_survives_an_unreachable_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        let got = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let a = Alert {
            severity: Severity::Critical,
            kind: "stalled".into(),
            message: "no ticks".into(),
            unix: 1,
        };
        WebhookNotifier::new(url).notify(&a).await;
        let req = got.await.unwrap();
        assert!(req.starts_with("POST /hook"), "{req}");
        assert!(req.contains("\"kind\":\"stalled\""), "{req}");

        // A dead endpoint must return (after retries), not hang or panic.
        let dead = WebhookNotifier::new("http://127.0.0.1:1/hook".into());
        tokio::time::timeout(Duration::from_secs(20), dead.notify(&a))
            .await
            .expect("notify must give up, not hang");
    }
}
