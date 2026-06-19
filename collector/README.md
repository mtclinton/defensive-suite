# collector

The aggregation keystone of the [defensive-suite](../README.md). Each tool emits
the same `Report`/`Finding` JSON to a webhook; the collector is the one webhook
they all POST to. It stores the findings and serves the
[dashboard](../dashboard/) with **live, local** data — the "one local collector"
the suite's architecture is built around.

A single static Go binary, standard library only.

## What it does

```
   authwatch ─┐
   instguard ─┤   POST Report JSON          ┌─ /            dashboard (embedded)
credsentinel ─┼──────────────────────────▶  │  /api/findings  current posture (JSON)
 egresswatch ─┤   Authorization: Bearer …   │  /api/summary   roll-up
 posturescan ─┤      → /ingest              │  /api/reports   recent reports
   bpfsentry ─┘                             └─ /healthz
```

- **`POST /ingest`** — bearer-token-gated, body-size-bounded. Accepts one tool's
  `Report` and stores it. Fails **closed**: no token configured → `503`.
- **`GET /api/findings`** — current posture: the latest report per (tool, host),
  flattened, sorted worst-first. Query params: `tool`, `severity`, `host`.
- **`GET /api/summary`** — counts by severity, worst, clean/not, per-tool status, hosts.
- **`GET /api/reports?limit=N`** — recent raw reports.
- **`GET /`** — the dashboard, which fetches `/api/findings` for live data.
- **`GET /healthz`**.

Storage is in-memory plus an atomic JSON snapshot on disk (survives restarts),
with age (`--retention-days`) and count (`--max-reports`) retention.

## Run

```sh
make static
COLLECTOR_TOKEN=$(openssl rand -hex 32) ./bin/collector --addr 127.0.0.1:8787 --data ./data
# dashboard → http://127.0.0.1:8787/
```

Point each tool's webhook at `http://<collector>:8787/ingest` with
`Authorization: Bearer <COLLECTOR_TOKEN>` (see [`deploy/README.md`](deploy/README.md)).

Quick self-test:

```sh
curl -s -XPOST -H "Authorization: Bearer $COLLECTOR_TOKEN" \
  -d '{"tool":"authwatch","host":"lab","findings":[{"check":"pam","severity":"critical","title":"unowned PAM module"}]}' \
  http://127.0.0.1:8787/ingest
curl -s http://127.0.0.1:8787/api/summary
```

## Configuration

Defaults are safe (loopback, 30-day retention). Override via flags or `COLLECTOR_*` env:

| Setting | Flag | Env | Default |
|---------|------|-----|---------|
| listen address | `--addr` | `COLLECTOR_ADDR` | `127.0.0.1:8787` |
| ingest token | `--token-file` | `COLLECTOR_TOKEN` | *(unset → ingest disabled)* |
| data dir | `--data` | `COLLECTOR_DATA_DIR` | `data` |
| age retention | `--retention-days` | `COLLECTOR_RETENTION_DAYS` | `30` |
| count cap | `--max-reports` | `COLLECTOR_MAX_REPORTS` | `5000` |

The token is read from the environment or a file (`--token-file`), never a
plaintext flag.

## Security

Bind a **private** interface only (loopback or Tailscale) — never `0.0.0.0` on an
untrusted network. Ingest is bearer-gated with a constant-time compare and a
bounded body; the read-only API/dashboard are unauthenticated and assume a
private interface. The collector holds findings, not credentials — keep it
separate from the off-host trust anchors.

## Layout

```
collector/
├── main.go                 # flags, embeds the dashboard, graceful shutdown
├── internal/
│   ├── store/              # report storage, retention, current-posture queries
│   ├── server/             # /ingest, /api/*, dashboard, /healthz
│   └── config/             # defaults + COLLECTOR_* env
├── web/index.html          # the dashboard, embedded into the binary
└── deploy/                 # systemd unit + env example
```
