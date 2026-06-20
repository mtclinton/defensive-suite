# agentd — arming enforcement (M4) runbook

> ⚠️ **REVIEW BEFORE RUNNING. VALIDATE IN A VM, NEVER FIRST ON THE DAILY DRIVER.**
> Every command below is shown for you to read, not auto-run. The build and the
> tests **load nothing, enable nothing, write no rule.** `agentd preflight` is
> **strictly read-only** — it inspects host state and never mutates anything.
> Arming enforcement turns SIGKILL-on-bpf-load into a live primitive; treat it
> with the same care as the response actuators in [`RESPONSE.md`](RESPONSE.md).

This is the **prevention** milestone: roll out **observe → enforce, one policy at
a time**, with explicit allow-lists. Nothing ships in enforce mode by default.

Artifacts referenced here (all shipped, none applied):

| File | What it is | State |
|------|------------|-------|
| `tetragon/dsuite-observe.yaml` | observe-only policy (M1) | watch findings |
| `enforce/dsuite-enforce.yaml` | the M4 enforce policy (SIGKILL non-allowlisted bpf loaders) | **arms blocking** |
| `enforce/sysctl/99-dsuite-hardening.conf` | kernel hardening drop-in | apply with `sysctl --system` |
| `enforce/fapolicyd/README` | block-hash deny-rule path | hand-maintained |
| `enforce/nftables/egress-baseline.nft` | optional logged-egress baseline | optional |

---

## (a) Run preflight and read it — READ-ONLY, mutates nothing

```sh
# No flags: prints a readiness table and sets the exit code.
agentd preflight
#   exit 0 → READY (no medium/high blockers)
#   exit 2 → NOT READY (a blocker — read the table + remedies)
#   exit 1 → the verifier itself errored

# Optionally record the readiness report in the collector (still read-only):
agentd preflight --post

# JSON for tooling:
agentd preflight --format json
```

It checks: kernel **BTF** (`/sys/kernel/btf/vmlinux`), **CONFIG_BPF_KPROBE_OVERRIDE**
(advisory — SIGKILL doesn't need it), **nftables**, **fapolicyd** (present+active),
**Tetragon** (binary + active + socket), the **kernel release**, whether any
**enforce policy is already loaded**, and **response readiness**
(`AGENT_RESPONSE_TOKEN` / `--enable-response`). It runs only `stat`, file reads,
`--version`, `systemctl is-active`, and `tetra … list` — **it loads no policy,
enables no enforcement, writes no sysctl/nft/fapolicyd rule.**

Do not proceed past a **high** blocker. A **medium** (e.g. nftables absent) means
the dependent feature won't work; decide per-feature. **info** gaps are advisory.

---

## (b) Install Tetragon — shown, not run

Tetragon runs standalone on any Linux host (not just Kubernetes). Install from a
released artifact and a systemd unit. (Links/versions current as of writing;
confirm the latest release yourself.)

```sh
# Option 1 — distro/.deb (Debian/Ubuntu). REVIEW the package + checksum first.
#   https://github.com/cilium/tetragon/releases
curl -fsSLO https://github.com/cilium/tetragon/releases/download/<TAG>/tetragon-<TAG>-amd64.deb
sha256sum tetragon-<TAG>-amd64.deb           # compare to the release checksum
sudo apt install ./tetragon-<TAG>-amd64.deb  # SHOWN — review before running

# Option 2 — tarball + systemd unit (also shown, not run):
#   tar x…; sudo cp tetragon /usr/local/bin/; sudo cp tetragon.service /etc/systemd/system/
sudo systemctl enable --now tetragon         # SHOWN — review before running

# Confirm the daemon + socket, then re-run preflight:
systemctl is-active tetragon
ls -l /var/run/tetragon/tetragon.sock
agentd preflight
```

The `tetra` CLI ships with Tetragon; it's how you load/list/delete policies.

---

## (c) Load the OBSERVE policy first — watch findings, do not block

```sh
# Load observe-only (NOTHING is killed; every match is reported):
sudo tetra tracingpolicy add tetragon/dsuite-observe.yaml
sudo tetra tracingpolicy list                 # confirm dsuite-observe is loaded

# Watch live events and confirm WHICH binaries load eBPF on your host — these are
# the loaders you MUST allow-list before arming enforce, or you'll SIGKILL them:
sudo tetra getevents -o compact | grep -i bpf

# agentd is already consuming these into findings (run mode). Let it run long
# enough to see your normal loaders (Cilium, Tetragon, your tracer, bpftool…).
```

Edit `enforce/dsuite-enforce.yaml`'s `matchBinaries: NotIn` allow-list to the
**absolute, symlink-resolved** paths you observed:

```sh
command -v cilium-agent tetragon bpfsentry
readlink -f $(command -v cilium-agent)        # resolve to the real ELF path
```

---

## (d) Flip ONE policy to enforce — the arming step (VM-first)

> This is the only step that arms blocking. Do it **in a VM first**, with the
> allow-list confirmed. Load **one** enforce policy at a time.

```sh
# Arm the eBPF-rootkit-load SIGKILL policy:
sudo tetra tracingpolicy add enforce/dsuite-enforce.yaml

# Confirm it loaded:
sudo tetra tracingpolicy list                 # expect dsuite-enforce present
agentd preflight                              # enforce-policy check now notes "may already be armed"
```

**Test the kill in the VM** (a non-allowlisted process loading an eBPF program
should be SIGKILLed; an allow-listed loader should NOT be):

```sh
# Negative control — a random binary loading a trivial BPF program should DIE.
# (Use a throwaway loader in the VM; e.g. a tiny program calling bpf(BPF_PROG_LOAD).)
./vm-test-bpf-loader            # expect: Killed (SIGKILL) + a Tetragon enforce event
sudo tetra getevents -o compact | grep -i sigkill

# Positive control — your allow-listed loader must keep working:
sudo systemctl restart tetragon # Tetragon reloads its own programs; must NOT be killed
systemctl is-active tetragon    # still active → allow-list is correct
```

If an allow-listed loader gets killed, your `NotIn` list is missing its path —
**delete the policy (rollback, below), fix the list, re-test in the VM.**

### Optional prevention baseline (also VM-first, also one at a time)

```sh
# Kernel hardening drop-in:
sudo install -m 0644 enforce/sysctl/99-dsuite-hardening.conf /etc/sysctl.d/99-dsuite-hardening.conf
sudo sysctl --system                          # review the changes first

# Optional logged-egress baseline (EDIT mgmt_iface/mgmt_net FIRST — lockout risk):
sudo nft -f enforce/nftables/egress-baseline.nft
sudo nft list table inet dsuite_egress

# fapolicyd deny rules — see enforce/fapolicyd/README; apply by hand, VM-first.
```

---

## (e) Enable manual response — set BOTH tokens (separate from enforcement)

Enforcement (Tetragon SIGKILL) and manual response (agentd's kill/isolate/…) are
independent. To also arm manual response (see [`RESPONSE.md`](RESPONSE.md)):

```sh
# Token is env-only (never a flag → not in the process table):
#   openssl rand -hex 32
export AGENT_RESPONSE_TOKEN=<long-random>

# Dry-run first (default): the socket serves, NOTHING is executed.
sudo AGENT_RESPONSE_TOKEN=$AGENT_RESPONSE_TOKEN agentd run --response-socket /run/agentd.sock

# Go LIVE only after VM validation (requires root):
sudo AGENT_RESPONSE_TOKEN=$AGENT_RESPONSE_TOKEN agentd run \
  --response-socket /run/agentd.sock --enable-response

# The collector needs the SAME token to proxy /api/respond (so the console can
# request actions). In /etc/collector/collector.env (0600):
#   COLLECTOR_AGENT_SOCKET=/run/agentd.sock
#   COLLECTOR_RESPONSE_TOKEN=<same value as AGENT_RESPONSE_TOKEN>
```

`agentd preflight`'s **response-readiness** check reports whether the token is set
and whether `--enable-response` / `AGENT_ENABLE_RESPONSE` would flip it out of
dry-run — read-only, it enables nothing.

---

## (f) ROLLBACK — every step is reversible

```sh
# Enforcement (the arming step) — remove the enforce policy:
sudo tetra tracingpolicy delete dsuite-enforce
#   → SIGKILL-on-bpf-load is disarmed. (Observe can stay loaded.)
sudo tetra tracingpolicy delete dsuite-observe   # if you also want observe off

# Sysctl hardening:
sudo rm /etc/sysctl.d/99-dsuite-hardening.conf && sudo sysctl --system

# nftables egress baseline (dedicated table → clean removal):
sudo nft delete table inet dsuite_egress

# fapolicyd deny rules:
sudo rm /etc/fapolicyd/rules.d/50-dsuite.rules && sudo fapolicyd-cli --update

# Manual response: stop the LIVE agentd; rerun without --enable-response (dry-run),
# or drop the socket entirely. The M3 isolate/quarantine/etc. each return an
# `undo` string — see RESPONSE.md's reversibility table.
```

---

### Summary of the discipline (the design's non-negotiables)

- **observe → enforce, one policy at a time.** This bundle arms exactly one hook
  (bpf-load SIGKILL); the file-write and exec hooks stay observe-only in P1.
- **Allow-list your loaders before arming**, or you SIGKILL Cilium/Tetragon/your
  tracer. Confirm them in observe mode first.
- **SIGKILL needs no `CONFIG_BPF_KPROBE_OVERRIDE`**; that option is only for the
  later `Override` blocking — which is why preflight rates it advisory/medium.
- **VM-first, always.** Enforcement can brick a daily driver.
- **bpfsentry stays the out-of-band trust backstop** — agentd is never the sole
  source of truth (a kernel implant can lie to the on-host agent).
