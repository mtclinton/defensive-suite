# egresswatch — DESIGN

**Threats:** IronWorm Tor C2, easy-day-js stage-two beaconing, exfil pipelines in
QLNX/`deps`, and BPFDoor/Symbiote magic-packet backdoors.

## What it does

Per-process outbound visibility plus passive-backdoor detection. The blog's malware all
phones home; most Linux setups watch inbound and are blind to egress.

**(a) Application firewall.** Deploy OpenSnitch with its eBPF backend — attributes every
new outbound connection to a process/path and lets you allow/deny, surfacing "why is this
`node <hex>.js` connecting to 23.254.164.123?"

**(b) Magic-packet detector.** A small eBPF/Go sensor (or Falco rule) that alerts when any
process calls `setsockopt` to attach a BPF filter to an `AF_PACKET` / raw socket — the
BPFDoor/Symbiote signature. Optionally feed mirrored traffic to Suricata/Zeek with rules
for the documented BPFDoor markers (the hardcoded `1234` sequence number; the technically
invalid ICMP Code 1 injected by the heartbeat thread).

## Build

- **OpenSnitch:** install-and-configure; needs a modern kernel with BTF.
- **Sensor:** Go + `cilium/ebpf`, or a Falco rule
  (`condition: setsockopt + SO_ATTACH_FILTER on AF_PACKET`) — Sysdig has published one.
- **Learn from:** Rapid7's BPFDoor triage script (`rapid7_detect_bpfdoor.sh`) — checks
  `AF_PACKET` raw sockets, attached BPF filters, zero-byte mutex files, fileless
  `(deleted)` exec, kernel stacks blocked on `packet_recvmsg`.

## What it verifies

An allowlist of expected egress (package mirrors, Tailscale, known services); anything
else prompts or logs. Zero processes with BPF filters on raw sockets = no BPFDoor-class
implant present.

## Homelab fit

OpenSnitch on each workstation; Suricata/Zeek tap on the homelab gateway. Sensor runs at
<3% CPU on the 5950X.

## Effort

1 week for OpenSnitch + Falco rule; 2 weeks with the custom eBPF sensor + Suricata integration.