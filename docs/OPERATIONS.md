# Operating the daemon

What to watch, what the alerts mean, and what is *not* covered. The design
goal (SECURITY.md T3) is that "Tripwire is down" can never look like
"Tripwire looked and found nothing".

## Endpoints

Served on `TRIPWIRE_METRICS_ADDR` (default `127.0.0.1:9464`; empty disables).
Loopback by default. If you bind further, put something in front that
authenticates it: the endpoint is read-only but reveals operational state.

| Path | Purpose |
|---|---|
| `/healthz` | `200 ok`, or `503 <state>: <reason>`. Use for load-balancer / Kubernetes probes. |
| `/metrics` | Prometheus text format. |
| `/status` | The same state as JSON. |

## States

| State | Meaning | Typical cause |
|---|---|---|
| `never_ticked` | No successful tick since start, past the startup grace. | Bad RPC URL, node down at boot. |
| `stalled` | No successful tick for `TRIPWIRE_STALE_AFTER_SECS` (30). | RPC outage, or a hung call. |
| `failing` | `TRIPWIRE_MAX_TICK_FAILURES` (5) failed ticks in a row. | Rate limiting, RPC errors. |
| `chain_not_advancing` | Ticks succeed but the head has not moved for `TRIPWIRE_CHAIN_STALL_AFTER_SECS` (300). | **Stale or eclipsed RPC**, or a halted chain. |
| `pause_failing` | The last tick decided to pause and the transaction failed. | Hot wallet out of gas, role revoked, target not registered. **Most urgent.** |

Set `chain_not_advancing` to something above your chain's worst normal gap
(rollups with sparse blocks need a larger value than Ethereum mainnet).

## Alerts

Transitions to unhealthy, recoveries, reminders (every
`TRIPWIRE_ALERT_REMINDER_SECS`, default 600) and every pause are sent to
`TRIPWIRE_ALERT_WEBHOOK_URL` as JSON, with a `text` field that Slack- and
Discord-style webhooks render directly:

```json
{"severity":"critical","kind":"stalled","message":"...","unix":1790003596,"text":"[tripwire CRITICAL] ..."}
```

Alerts are **always** also logged (`ERROR ... ALERT:`), so an unset or dead
webhook does not lose them. The webhook has a 5 s timeout and 3 retries and
can never take the daemon down.

A change of *reason* alerts immediately (e.g. `stalled` -> `pause_failing`),
without waiting for a reminder.

The watchdog runs in its own task, independent of the detection loop, so a
tick that hangs is still reported. Ticks are cancelled after
`TRIPWIRE_TICK_TIMEOUT_SECS` (120) and counted as failures; keep this above
the worst-case pause submission time (`attempts x attempt timeout`, see
`TRIPWIRE_PAUSE_*`).

## Suggested Prometheus rules

```yaml
- alert: TripwireUnhealthy
  expr: tripwire_healthy == 0
  for: 1m
  labels: {severity: critical}
- alert: TripwireNotScraped          # the daemon itself is gone
  expr: absent(tripwire_healthy) or up{job="tripwire"} == 0
  for: 1m
  labels: {severity: critical}
- alert: TripwireStaleListener
  expr: tripwire_seconds_since_last_successful_tick > 60
  labels: {severity: critical}
```

The second rule matters most: the process dying takes its own health
endpoint with it, so an *external* check that the endpoint is reachable is
the only thing that catches a crash. Run the daemon under a supervisor
(systemd, Kubernetes) and scrape it from a separate host.

## What this does not cover

- A compromised or malicious RPC that serves a *plausible, advancing* but
  false chain. Liveness sees a healthy listener; this is the residual risk
  in SECURITY.md T3, mitigated only by using more than one independent
  provider (not implemented).
- The daemon host being down together with the alerting path. The webhook and
  the scrape both depend on the network.
- Detection quality. A healthy listener says nothing about false negatives.
