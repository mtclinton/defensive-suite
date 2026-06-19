# credsentinel — deployment

credsentinel ships these artifacts but **installs nothing automatically**. Every
privileged command below is shown for you to review and run yourself.
credsentinel's `scan` only ever *reads* the filesystem and *reports*; `deploy`
*writes decoy files* (into the home dir by default — never over your real
`~/.aws/credentials`); neither ever loads auditd rules or changes the kernel.

```
deploy/
├── systemd/credsentinel-scan.service     # oneshot, hardened, runs `scan --with-honeytokens`
├── systemd/credsentinel-scan.timer       # 4x/day + on-boot, randomized delay
├── audit/credsentinel-honeytokens.rules  # auditd read-watches on the decoys (SHIPPED, NOT LOADED)
├── sigma/lnx_auditd_credsentinel_honeytoken_read.yml   # T1552.001 — decoy accessed
├── config.example.json                   # copy to /etc/credsentinel/config.json
└── credsentinel.env.example              # secrets/token data — env-only, 0600
```

## 1. Install the binary

```sh
make static                                    # builds bin/credsentinel (CGO-free, static)
sudo install -m 0755 bin/credsentinel /usr/local/bin/credsentinel
```

## 2. Configuration (no secrets in source)

```sh
sudo install -d -m 0750 /etc/credsentinel
sudo install -m 0640 deploy/config.example.json /etc/credsentinel/config.json

# Secrets and token data come from the environment, NEVER the config file:
sudo install -m 0600 deploy/credsentinel.env.example /etc/credsentinel/credsentinel.env
sudoedit /etc/credsentinel/credsentinel.env      # set CREDSENTINEL_WEBHOOK_AUTH, CREDSENTINEL_CANARY_HOST
```

Edit `/etc/credsentinel/config.json` so `scan_roots` lists your repo trees and
home, and `manifest_path` points where the honeytoken manifest should live (back
it up off-host — it is the trip baseline).

## 3. Optional: install the external scanners

credsentinel works with neither installed (its built-in fallback scanner covers
the stealer-target files), but the full picture wants both:

```sh
# gitleaks — fast regex secret detection (pre-commit class)
# trufflehog — verifies whether a found credential is LIVE against the provider API
#   credsentinel runs:  trufflehog filesystem <path> --json --results=verified
#   so only confirmed-live hits come back (a verified hit = Critical "rotate now").
# Install per upstream; both are single Go binaries on PATH.
```

## 4. Plant the honeytokens (run as the workstation user)

```sh
# Optional but recommended: weave a self-hosted DNS token into the .env decoy.
export CREDSENTINEL_CANARY_HOST=abc123.canary.your-homelab.internal
credsentinel deploy --config /etc/credsentinel/config.json
# Prints each decoy's path + sha256 and writes the manifest. Back the manifest up
# off-host. Decoys land at (defaults):
#   ~/.aws/credentials.bak        (fake AWS key block, AKIA-prefixed, dead)
#   ~/.kube/decoy.kubeconfig      (unroutable TEST-NET cluster, dead token)
#   ~/.config/app/.env.decoy      (DNS-token hostname + dead DB/API creds)
```

## 5. systemd timer — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/credsentinel-scan.service /etc/systemd/system/credsentinel-scan.service
sudo install -m 0644 deploy/systemd/credsentinel-scan.timer   /etc/systemd/system/credsentinel-scan.timer
sudo systemctl daemon-reload
sudo systemctl enable --now credsentinel-scan.timer
# Smoke-test one run and read the journal:
sudo systemctl start credsentinel-scan.service
journalctl -u credsentinel-scan.service -n 50 --no-pager
```

> The unit runs as root by default; to scan a specific user's credential files and
> watch that user's decoys, add `User=` / `Group=` and point `CREDSENTINEL_HOME`
> at their home, or template the unit per user.

## 6. auditd watches on the decoys — REVIEW BEFORE RUNNING (changes auditd config)

This adds a **second, kernel-level** trip signal: a read of any decoy recorded at
the syscall level, independent of atime (which an attacker can defeat with a
`noatime` mount). credsentinel ships the rules but **never loads them**.

The shipped file uses placeholder paths; generate the exact lines from your
deployed decoys instead:

```sh
# Decoys must already exist (step 4) — auditd resolves -w paths at load time.
# Replace /home/CHANGEME with the real home, or derive exact lines from the
# manifest paths printed by `credsentinel deploy`.
sudoedit deploy/audit/credsentinel-honeytokens.rules
sudo install -m 0640 deploy/audit/credsentinel-honeytokens.rules /etc/audit/rules.d/credsentinel-honeytokens.rules
sudo augenrules --load                                  # compile + load all rules.d files
sudo auditctl -l | grep credsentinel_honeytoken         # confirm the watches are active
```

A hit on key `credsentinel_honeytoken` is a breach indicator — wire it to the
Sigma rule below.

## 7. Sigma rule

```sh
sigma convert -t <backend> deploy/sigma/lnx_auditd_credsentinel_honeytoken_read.yml
```

Feed the auditd events filtered by the `credsentinel_honeytoken` key to your SIEM.

## Self-hosting Canarytokens (Thinkst) behind Tailscale

credsentinel's built-in honeytoken generator is the from-scratch, full-control
path. If you also want classic Canarytokens (DNS/HTTP/AWS-key tokens with rich
alerting), **self-host the Thinkst OSS Canarytokens server on the homelab rather
than using canarytokens.com**:

- Run the Canarytokens Docker stack on an internal host; expose it **only over
  Tailscale**, not the public internet. This keeps all token data on your infra
  and avoids the `canarytokens.com` DNS fingerprint an attacker can recognise and
  skip.
- Point its alert channel at a **local webhook** — the same collector credsentinel
  POSTs to over Tailscale — so DNS-token trips and credsentinel's own trips land
  in one place.
- Mint a DNS token from your self-hosted server and put its hostname in
  `CREDSENTINEL_CANARY_HOST`; credsentinel weaves it into the `.env` decoy, so an
  exfiltrated `.env` that gets used resolves your token host and fires the alert
  even off the original machine.

## Reduce the blast radius (structural hardening)

A tripwire tells you a file was stolen; structural hardening makes the stolen file
worth less. Pair credsentinel with **short-lived, file-less credentials**:

- **npm / PyPI publishing → OIDC Trusted Publishers.** Move package publishing off
  long-lived `~/.npmrc` / `~/.pypirc` tokens to OIDC Trusted Publishers (GitHub
  Actions identity → registry), so there is no durable token on disk for a stealer
  to harvest.
- **Kubernetes → workload-identity federation.** Replace static `~/.kube/config`
  tokens with workload identity / short-TTL OIDC so a stolen kubeconfig expires in
  minutes, not months.
- **AWS → SSO / role assumption** over long-lived `~/.aws/credentials` access keys,
  for the same reason.

Then credsentinel's exposure scan should find *nothing durable* in those paths, and
its honeytokens stand alone as the breach indicator.

## Uninstall

```sh
sudo systemctl disable --now credsentinel-scan.timer
sudo rm -f /etc/systemd/system/credsentinel-scan.{service,timer} && sudo systemctl daemon-reload
sudo rm -f /etc/audit/rules.d/credsentinel-honeytokens.rules && sudo augenrules --load
# Remove the planted decoys (paths from the manifest), then:
sudo rm -rf /etc/credsentinel /usr/local/bin/credsentinel
```
