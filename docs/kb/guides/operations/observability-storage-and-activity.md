---
title: Observability, storage and Activity
summary: Use logs, metrics, captures and the Activity view to diagnose requests and retain useful history.
category: guides
tags: [operations, logs, metrics, activity, captures, stdout, http]
config_keys: [logLevel, logToStdout, metricsMaxInMemory, captureBuffer, tailscale, tailscale.enabled, tailscale.trackDevice, store.path]
updated: 2026-10-14
---

# Observability, storage and Activity

Use the Activity view for recent request timing and model events, logs for
process and proxy failures, and metrics for trends. `metricsMaxInMemory` and
`captureBuffer` bound retained in-memory data; increase them only when the
memory cost is acceptable.

```yaml
logLevel: debug
logToStdout: "proxy,http"
metricsMaxInMemory: 1000
captureBuffer: 100
```

## Log streams

llama-swap keeps three log streams. Each has its own tab on the UI's Logs page
and its own endpoint, `GET /logs/stream/<stream>`:

- `proxy`: llama-swap's own messages, such as model swaps, loading and errors.
- `upstream`: a copy of the upstream processes' stdout and stderr.
- `http`: one access log line per HTTP request (client, method, path, status,
  size, duration).

`logToStdout` chooses which streams are also written to stdout. It takes a
comma separated list such as `"proxy,http"` or `"upstream,http"`, or one of
`"both"` (every stream) and `"none"`. The default is `"proxy"`.

What goes wrong:

- HTTP access lines used to be part of the proxy log. With the default
  `"proxy"` they no longer reach stdout. Use `"proxy,http"` to keep them.
- A value outside the list, like `true` or `"proxy,debug"`, fails config
  loading.
- `logToStdout` is read at startup only. Restart llama-swap after changing it.

Do not put secrets in captures or debug logs. Reduce retention after diagnosing
an issue.

## Tailscale caller identity

Enable **User** (stable label) and **User ID** (numeric Tailscale user ID) in
active requests, saved activity and exports:

```yaml
tailscale:
  enabled: true
  trackDevice: false
store:
  path: /path/to/activity.sqlite
```

Direct tailnet connections use the local daemon's WhoIs API. The llama-swap
process needs access to that daemon. Identity/forwarding headers are ignored;
connections through a proxy identify the proxy, not its original caller.
Missing user IDs or hostnames show `-`, with no email or MagicDNS fallback.
Tagged devices have no human user. Activity stores the assigned label and user
ID, with IDs encoded as decimal strings to preserve every digit in the UI.
Device tracking is off by default: hostnames are not collected into RAM or
saved with new activity or identity cache entries, and the Device column is
unavailable. Set `tailscale.trackDevice: true` to collect hostnames and show
that column again. The two modes use separate IP cache keys, so disabling
device tracking cannot reuse a cached hostname. Previously saved history and
cache entries remain; old records are not backfilled. These settings do not
change authentication.

Each Tailscale user ID gets one label on first use, shared across devices.
The first person keeps their display name. A later namesake gets the last
word’s initial when it is a letter, otherwise a full user-ID suffix such as
`Alex [123]`. Suffixes repeat if needed to avoid another reserved label.
Comparison ignores case and normalizes whitespace. Assigned labels never
change when a profile is renamed or another namesake appears. Empty display
names use `User [123]`. Labels are reserved in the existing SQLite cache and
survive restart with a file-backed store. Older IP cache entries are checked
again once after this upgrade; existing history keeps its recorded labels.

Unknown IPs wait up to 500 ms for a lookup. Concurrent requests from the same
IP share that lookup; canceling one request does not cancel it for others.
Known identities are used immediately. After one hour, the next request
starts a background refresh; idle IPs are not polled. Failed refreshes retain
the last known identity and retry on a later request after five seconds.
Each request keeps its original identity snapshot, including saved activity.
RAM keeps the 65,536 most recently used IPs. Older entries are evicted when new
IPs arrive; their saved identities remain in SQLite and reload on demand.

Successful identities and the last successful lookup time use the existing
SQLite cache. Set `store.path` to a file to retain them across restarts and
config reloads; the default in-memory store loses both cache and activity
when closed. Saved identities are read on demand and used even when stale,
while a background refresh checks for changes. Model unloads and process
pause/resume retain the cache. Shutdown cancels and drains lookups before
closing the store; executing HTTP requests cannot resume after a restart.

What goes wrong: disabled attribution, non-tailnet clients, initial daemon
failures or an unreadable user-label registry leave names unknown; inference
continues. Initial failures are cached in memory for five seconds. Cache
read/write errors are logged and inference continues, but failed writes lose
the new identity on restart.
Stale names may remain visible during daemon outages or after an IP changes
owner; these display fields must not be used for authorization.
