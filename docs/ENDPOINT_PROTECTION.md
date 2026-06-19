# Endpoint Protection — evolution design

**Status:** design / decision doc. No code committed against this yet.
**Question it answers:** can `defensive-suite` become an endpoint-protection program,
and if so, what is the honest scope, architecture, and build-vs-buy?

**Scope guardrail:** the target is a **personal / homelab Linux** endpoint-protection
system, not a commercial EPP. Competing with CrowdStrike/SentinelOne-class products is an
explicit non-goal (thousands of engineer-years, signature pipelines, 24×7 threat-intel,
multi-OS). Where mature OSS already solves a platform problem, we **integrate, not
reinvent**.

## 1. Vocabulary (these get conflated)

| Term | What it means | Verb |
|------|---------------|------|
| **EPP** | Endpoint *Protection* Platform — AV/anti-malware, app allow-listing, device/exec control, host firewall, exploit mitigation | **prevent** |
| **EDR** | Endpoint *Detection & Response* — continuous telemetry → behavioral detection → investigation → response | **detect + respond** |
| **XDR** | EDR extended across network/cloud/identity with central correlation | **correlate** |

"Modern endpoint protection" = EPP + EDR. `defensive-suite` today is a strong slice of the
**detection + visibility** half. The work is adding *continuous collection*, *response*,
and *prevention*.

## 2. Where we are (capability baseline)

| EDR/EPP pillar | defensive-suite today | Gap |
|----------------|----------------------|-----|
| Telemetry collection | scheduled point-in-time scans → journald + webhook | no **continuous** stream of exec/file/net/`bpf()` events |
| Detection content | 6 specialized detectors, ATT&CK-mapped findings, shipped Sigma/Falco/Tetragon/auditd rules | rules aren't evaluated **live**; little cross-signal correlation |
| Aggregation / console | the `collector` + dashboard (live, local) | read-mostly; no real-time **alerting**, case/triage workflow |
| Investigation / hunting | findings + report JSON | no raw-event store, timeline, or query interface |
| **Response** | none (posturescan remediation is dry-run only) | **the headline gap** — no kill/isolate/quarantine/revoke |
| **Prevention** | designed but **off**: posturescan sysctls, Tetragon `SIGKILL` (shipped commented out), app-allowlist hooks | not enabled / enforced |
| Management | manual per-host deploy | no policy push, agent lifecycle, fleet inventory |
| Self-protection | **bpfsentry out-of-band** (early-boot baseline + memory forensics) | on-host agent tamper-resistance not built |

Two of these are differentiators worth keeping: the **specialized detectors** (PAM/OpenSSH
backdoors, supply-chain, eBPF-rootkit forensics) and the **out-of-band assurance** thesis —
most EPPs have neither.

## 3. Target architecture

```
        ┌──────────────── endpoint (agent) ─────────────────┐
        │  real-time sensors        scheduled detectors     │
        │  Tetragon/Falco/auditd    authwatch · instguard   │
        │  (exec,file,net,bpf load) credsentinel · egress…  │
        │            │                      │               │
        │            └────── detection engine ──────┐       │
        │            (stream + periodic, rule-based) │       │
        │                                            ▼       │
        │   prevention/enforce ◀── response actuators (local)│
        │   (sysctl, SIGKILL,      kill · isolate · quarantine│
        │    fapolicyd)            revoke-key · block-hash    │
        └───────────────────────────┬───────────────────────┘
                                     │ findings + events (mTLS, Tailscale)
                                     ▼
        ┌──────────────── collector / server ────────────────┐
        │  ingest · store · correlate · alert · dashboard      │
        │  policy distribution · response orchestration        │
        │  fleet inventory · RBAC                               │
        └─────────────────────────┬───────────────────────────┘
                                   │ trusted, off-host
                                   ▼
                 out-of-band assurance (bpfsentry)
                 KVM memory snapshots · prog_idr walk
```

The `collector` we already built is the seed of the server tier. The new work is the
**agent**, the **response/prevention** layer, and **management**.

## 4. Build vs. buy (per component)

| Component | Build ourselves | Mature OSS | Call |
|-----------|-----------------|-----------|------|
| Real-time syscall/eBPF stream + **enforcement** | cilium/ebpf (we started in egress/bpfsentry) | **Tetragon** (enforce, SIGKILL), **Falco** (rules) | **Integrate** — we already ship policies for both |
| Endpoint inventory / SQL telemetry | — | **osquery** (+ Fleet) | **Integrate** when we want host-state queries |
| Agent + manager + fleet + active-response | custom daemon + control plane | **Wazuh** (agent/manager/active-response), **Velociraptor** (DFIR/hunt) | **Integrate** the platform; don't rebuild it |
| Console / aggregation | **our `collector` + dashboard** (done) | Wazuh dashboard, Elastic, Grafana | **Keep ours** — lightweight, ours, already live |
| Detection content | **our 6 detectors** (done) | generic rule packs | **Keep ours** — the differentiator |
| Out-of-band forensics | **bpfsentry** (done) | Velociraptor (on-host) | **Keep bpfsentry** — uniquely off-kernel |
| Response actuators | thin Go layer | Wazuh active-response, Tetragon enforce | **Hybrid** — small orchestration calling proven primitives |

**Recommendation:** a **hybrid**. Use Tetragon/Falco (+optionally Wazuh or osquery/Fleet)
for the platform plumbing — streaming, enforcement, fleet, active-response primitives — and
keep our detectors + collector + bpfsentry as the differentiated layer on top. Build only
the glue: the agent that unifies our detectors with the live stream, and the
response-orchestration that turns a confirmed finding into an action with guardrails.

## 5. Phased roadmap

Each phase is independently useful; stop at any point.

| Phase | Goal | Build | Integrate | Exit criteria |
|-------|------|-------|-----------|---------------|
| **0. Foundation** *(done)* | detect + visualize | 6 detectors, collector, dashboard | — | findings flow to a live console |
| **1. Continuous agent** | detection becomes real-time | agent that runs detectors on-trigger + ships a normalized event/finding stream to the collector | Tetragon/Falco/auditd as the event source | exec/file/net/`bpf()` events appear in the collector within seconds |
| **2. Response (manual)** | act on a finding | response actuators (kill PID, network-isolate via nftables, quarantine file, revoke `authorized_keys`, block hash) + a **dashboard action panel** with audit log | Wazuh active-response / Tetragon enforce as primitives | operator can contain a host from the console; every action is logged + reversible where possible |
| **3. Prevention** | block, don't just watch | enable what's designed: posturescan sysctls *applied*, Tetragon `SIGKILL` for confirmed `bpf()`-rootkit loads, app-allow-listing (fapolicyd) | fapolicyd, Tetragon enforce | a known-bad exec / rootkit load is blocked, not just alerted |
| **4. Automated response** | sub-second containment for high-confidence | policy: which findings auto-act (e.g. TruffleHog *verified* + Canarytoken trip → isolate), with rate limits, allow-lists, dead-man switch | — | a confirmed critical contains the host without a human, safely |
| **5. Management + self-protection** | fleet + tamper-resistance | signed policy push, agent heartbeat/inventory, RBAC on the collector; harden the agent | Wazuh manager / Fleet | policies push to N hosts; agent tamper is detected out-of-band (bpfsentry) |

**Suggested first step:** Phase 1 + a thin slice of Phase 2 (real-time stream → collector +
a manual response panel). Highest value per effort, builds directly on the collector, and
keeps a human in the loop before any automation.

## 6. Threat-model deltas (becoming an EPP changes the threat surface)

Adding response/prevention is powerful and therefore dangerous. New risks, with mitigations:

| New risk | Why it appears | Mitigation |
|----------|---------------|------------|
| **The agent is now a high-value target** | it runs privileged, can kill/isolate | least privilege per action (caps, not root-all); the destructive actuators gated behind a separate, auditable path |
| **Response actions are a weaponizable DoS/oppression primitive** | a hijacked "isolate/kill" playbook can take down the host or fleet | human-in-loop for destructive actions by default; rate limits; allow-lists of killable/isolable targets; dead-man/rollback; signed playbooks |
| **The control plane (collector) becomes critical** | it now pushes policy and triggers response | mTLS, signed policies, RBAC, append-only audit log, private network only |
| **Automated response can be induced** | attacker triggers a false "critical" to make the system isolate a host | require *corroborated/verified* signals (the suite already favors verified hits) before auto-action; confidence thresholds |
| **On-host agent gets lied to by a kernel rootkit** | the suite's own thesis (eBPF rootkits defeat on-box tools) | this is why **bpfsentry's out-of-band path stays the assurance backstop** — never trust the live agent as the sole truth |

The last row is the key architectural commitment: **no single on-host component is trusted
as ground truth.** Out-of-band verification (bpfsentry: early-boot baseline, KVM memory
snapshots, `prog_idr` walk) remains the tie-breaker — a property most commercial EPPs lack.

## 7. Non-goals & honest limitations

- **Not** a commercial/multi-OS EPP, signature AV, or a managed threat-intel service.
- **Not** a replacement for Wazuh/Falco/Tetragon — it *rides on* them.
- **Self-protection against a privileged kernel implant is unsolved on-host** by anyone;
  we mitigate with out-of-band assurance, not pretend to prevent it.
- **Response safety is the hard part**, not the easy "kill the process" demo — false
  positives that auto-isolate your own workstation are the realistic failure mode. Manual
  first, automation last, always reversible.
- Maintenance burden of a continuous agent (updates, performance, reliability) is real and
  ongoing — a reason to lean on maintained OSS for the plumbing.

## 8. Open decisions (for you)

1. **Single host or fleet?** (changes whether we need Phase 5 management at all.)
2. **Appetite for automated response?** (Phase 4 — or stay manual-only forever, which is a
   legitimate, safer choice for a personal machine.)
3. **Integrate Wazuh/Falco/Tetragon, or keep it minimal** (Tetragon + our collector only)?
4. **Prevention now or later?** (Phase 3 enables blocking — higher value, higher
   foot-gun risk on a daily-driver machine.)

Resolve 1–4 and the roadmap collapses to a concrete, scoped build.
