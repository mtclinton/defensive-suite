# collector — deployment

The collector is a long-running service (unlike the tools, which are scheduled
oneshots). Bind it to a **private** interface and gate ingest with a bearer
token. Every command below that touches the system is shown for you to **review,
not auto-run**.

## 1. Install the binary

```sh
make static
sudo install -m 0755 bin/collector /usr/local/bin/collector
```

## 2. Token + config (no secrets on the command line)

```sh
sudo install -d -m 0750 /etc/collector
sudo install -m 0600 deploy/collector.env.example /etc/collector/collector.env
# set COLLECTOR_TOKEN to a long random value (e.g. `openssl rand -hex 32`):
sudoedit /etc/collector/collector.env
```

## 3. systemd service — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/collector.service /etc/systemd/system/collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now collector.service
systemctl status collector.service
journalctl -u collector.service -n 30 --no-pager
```

The dashboard is then at `http://127.0.0.1:8787/` (open an SSH tunnel, or set
`--addr` to the host's Tailscale IP to reach it from your laptop).

## 4. Point each tool at the collector

Every tool reads its webhook URL + auth from config/env. Set them to the
collector's `/ingest` and the bearer token (same value as `COLLECTOR_TOKEN`):

```sh
# example for authwatch; each tool has its own <TOOL>_WEBHOOK_* env prefix
AUTHWATCH_WEBHOOK_URL='http://collector.tailnet.ts.net:8787/ingest'
AUTHWATCH_WEBHOOK_AUTH='Bearer <the COLLECTOR_TOKEN value>'
```

or in each tool's `config.json`:

```json
{ "webhook_url": "http://collector.tailnet.ts.net:8787/ingest" }
```

(the auth header stays env-only). On the next scheduled run each tool POSTs its
`Report` JSON; the dashboard updates to live data automatically.

## Security notes

- **Never bind `0.0.0.0` on an untrusted network.** Default is loopback; use a
  Tailscale/WireGuard interface for fleet ingest.
- Ingest **fails closed** — with no `COLLECTOR_TOKEN` set, `/ingest` returns 503.
- The read-only `/api/*` and dashboard are unauthenticated; they are meant to sit
  on the same private interface. Put them behind your reverse proxy / SSO if you
  expose them more widely.
- The collector receives findings but holds no credentials; keep it distinct from
  the off-host **trust anchors** (AIDE DBs, baselines, BPF allowlists), which the
  monitored machines must be able to write but not read or rewrite.
