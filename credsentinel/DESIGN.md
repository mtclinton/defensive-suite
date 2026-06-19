# credsentinel — DESIGN

**Threats:** every credential stealer on the blog (QLNX, atomic-lockfile `deps`,
easy-day-js stage two) targets the same files; the Private-CISA leak shows the at-rest risk.

## What it does

Two halves.

**(a) Exposure scanner.** Runs gitleaks (fast regex, pre-commit) and TruffleHog (verifies
whether a found credential is *live* against the provider API) across repos, home
directory, and the exact paths the stealers walk:
`.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, `.kube/config`,
`.docker/config.json`, `~/.codex/auth.json`, SSH keys, Vault tokens.

**(b) Tripwires.** Plants Canarytokens — a fake AWS key in `~/.aws/credentials.bak`, a
decoy `kubeconfig`, a DNS-token hostname in a fake `.env` — so any process reading them
fires an alert. No legitimate process touches a decoy credential, so a trip is a
near-zero-false-positive breach indicator.

## Build

- **Language:** Go or Python orchestrator wrapping gitleaks + TruffleHog, config tuned to
  the stealer target list. Use TruffleHog `--results=verified` to cut triage to live creds.
- **Honeytokens:** self-host Canarytokens (Thinkst OSS) on the homelab behind Tailscale —
  keeps token data on your infra and avoids the canarytokens.com DNS fingerprint; deliver
  alerts to a local webhook. A ~200-line Go honeytoken generator is a clean from-scratch
  alternative if you want full control.

## What it verifies

"0 live credentials found in scanned paths; 4 honeytokens deployed and quiet." A
TruffleHog verified hit → rotate now. A Canarytoken trip → assume compromise.

## Reduce the blast radius

Pair with structural hardening: move npm/PyPI publishing to short-lived OIDC Trusted
Publishers and Kubernetes access to workload-identity federation, so a stolen file is
worth less.

## Effort

Weekend. Scanner is an afternoon; self-hosting Canarytokens + seeding decoys is the rest.