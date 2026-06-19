# bpfsentry — deployment

bpfsentry ships these artifacts but **installs nothing automatically**. Every
command below is privileged and changes system state (systemd, Tetragon, Tracee,
auditd, the BPF subsystem). Review each one before you run it. `bpfsentry` itself
only ever *enumerates* the BPF subsystem (via `bpftool`) and *reports*; it loads
no eBPF of its own.

```
deploy/
├── systemd/bpfsentry-baseline.service   # EARLY-BOOT: capture the allowlist before agents load
├── systemd/bpfsentry-diff.service       # re-enumerate + diff vs allowlist
├── systemd/bpfsentry-diff.timer         # daily + on-boot, randomized delay
├── tetragon/bpfsentry-bpf-load.yaml     # kprobe on security_bpf_prog_load/bpf_check, PID-allowlist, optional SIGKILL
├── tracee/bpfsentry-tracee-policy.yaml  # bpf_attach / security_bpf_prog / hidden_kernel_module
├── audit/bpfsentry.rules                # -S bpf -k bpf_activity (and bpffs pin watch)
├── sigma/lnx_auditd_bpf_prog_load.yml   # T1014 / T1562.001
└── config.example.json                  # copy to /etc/bpfsentry/config.json
```

## Why three layers

The whole tool exists because an eBPF rootkit that hooks `sys_bpf` hides from
every live, on-box tool — including `bpftool` and eBPF EDR. So:

1. **Early-boot allowlist** (`bpfsentry-baseline.service`) — captured *before*
   any third-party agent or implant loads, then diffed later.
2. **Load-time alerting** (Tetragon / Tracee / auditd) — catch the rootkit at the
   instant it calls `bpf(BPF_PROG_LOAD)`, before it can hide.
3. **Out-of-band memory forensics** (`../forensics/`) — the only path that can't
   be lied to. A divergence between the live `bpftool` view and the memory-dump
   `prog_idr` walk is itself proof of a `sys_bpf`-hooking rootkit.

## 1. Install the binary

```sh
make static                                  # builds bin/bpfsentry (CGO-free, static)
sudo install -m 0755 bin/bpfsentry /usr/local/bin/bpfsentry
```

`bpftool` must be installed (`linux-tools-$(uname -r)` on Debian/Ubuntu,
`bpftool` package on RHEL/Fedora) — bpfsentry shells out to it for the portable
enumeration path.

## 2. Configuration (no secrets in source)

```sh
sudo install -d -m 0750 /etc/bpfsentry
sudo install -m 0640 deploy/config.example.json /etc/bpfsentry/config.json
# Webhook auth token comes from the environment, never the config file:
printf 'BPFSENTRY_WEBHOOK_AUTH=Bearer %s\n' "$TOKEN" | sudo tee /etc/bpfsentry/bpfsentry.env >/dev/null
sudo chmod 0600 /etc/bpfsentry/bpfsentry.env
```

Edit `/etc/bpfsentry/config.json` so `baseline_path` points at the **off-host**
trust anchor (a mount this host can write during early boot but not rewrite
afterward), and set `allowed_loaders` to the program names YOUR real agents load.

The shipped `config.example.json` sets `baseline_path` to
`/mnt/trust-anchor/bpfsentry-allowlist.json`, and `bpfsentry-baseline.service`
lists `/mnt/trust-anchor` in `ReadWritePaths` so its `ProtectSystem=strict`
sandbox does not make the write fail `EROFS`. Bind-mount your off-host anchor at
`/mnt/trust-anchor` (writable during the early-boot capture window, read-only to
this host afterward):

```sh
sudo install -d -m 0700 /mnt/trust-anchor
# Mount the off-host/read-only-after-boot anchor here, e.g. via /etc/fstab.
```

If you instead keep the allowlist on a local path, set `baseline_path` to a file
under `/var/lib/bpfsentry` (also in the service's `ReadWritePaths`) and keep the
config, the service, and this README in agreement.

## 3. Early-boot allowlist  — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/bpfsentry-baseline.service /etc/systemd/system/bpfsentry-baseline.service
sudo systemctl daemon-reload
sudo systemctl enable bpfsentry-baseline.service     # runs at next boot, before agents
# One-off capture at a known-good state (do this on a freshly-booted, trusted host):
sudo bpfsentry baseline --config /etc/bpfsentry/config.json
# Then make the anchor read-only to this host. If the allowlist is writable on
# the box, a rootkit rewrites it and the diff is worthless.
```

## 4. Periodic diff timer  — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/bpfsentry-diff.service /etc/systemd/system/bpfsentry-diff.service
sudo install -m 0644 deploy/systemd/bpfsentry-diff.timer   /etc/systemd/system/bpfsentry-diff.timer
sudo systemctl daemon-reload
sudo systemctl enable --now bpfsentry-diff.timer
# Smoke-test one diff and read the journal:
sudo systemctl start bpfsentry-diff.service
journalctl -u bpfsentry-diff.service -n 50 --no-pager
```

To diff against last night's out-of-band snapshot (the thesis path), run the
forensics pipeline off-host (see `../forensics/`) and feed its JSON in:

```sh
sudo bpfsentry diff --config /etc/bpfsentry/config.json --oob /mnt/trust-anchor/oob-prog-idr.json
```

## 5. Tetragon load-time policy  — REVIEW BEFORE RUNNING (changes kernel tracing)

```sh
# Standalone Tetragon:
sudo tetra tracingpolicy add deploy/tetragon/bpfsentry-bpf-load.yaml
# Kubernetes / Cilium:
kubectl apply -f deploy/tetragon/bpfsentry-bpf-load.yaml
```

Edit the `NotIn` binary lists to match YOUR legitimate loaders first. The
`Sigkill` enforcement action is commented out — enable it only after the
allowlist is proven not to kill a legitimate agent on your host.

## 6. Tracee policy  — REVIEW BEFORE RUNNING (changes what Tracee instruments)

```sh
sudo tracee --policy deploy/tracee/bpfsentry-tracee-policy.yaml
# or (k8s):
kubectl apply -f deploy/tracee/bpfsentry-tracee-policy.yaml
```

## 7. auditd rules  — REVIEW BEFORE RUNNING (changes kernel audit state)

```sh
sudo install -m 0640 deploy/audit/bpfsentry.rules /etc/audit/rules.d/bpfsentry.rules
sudo augenrules --load                 # compile + load all rules.d files
sudo auditctl -l | grep -E 'bpf_activity|bpf_pin'   # confirm the rules are active
```

## 8. Sigma rule

Convert with `sigma` / `pySigma` for your SIEM, or feed the auditd events
(filtered by the `bpf_activity` / `bpf_pin` keys) to a backend that ingests Sigma:

```sh
sigma convert -t <backend> deploy/sigma/lnx_auditd_bpf_prog_load.yml
```

## Out-of-band forensics (privileged — documented, never run here)

The acquisition and Volatility commands in `../forensics/` are privileged and
out of scope for this build. They are documented there and intentionally not run.
A confirmed kernel-resident implant means **reinstall — do not clean.**

## Uninstall

```sh
sudo systemctl disable --now bpfsentry-diff.timer
sudo rm -f /etc/systemd/system/bpfsentry-baseline.service
sudo rm -f /etc/systemd/system/bpfsentry-diff.{service,timer}
sudo systemctl daemon-reload
sudo rm -f /etc/audit/rules.d/bpfsentry.rules && sudo augenrules --load
sudo tetra tracingpolicy delete bpfsentry-bpf-load 2>/dev/null || true
sudo rm -rf /etc/bpfsentry /usr/local/bin/bpfsentry
```
