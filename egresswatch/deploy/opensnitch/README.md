# OpenSnitch — install-and-configure notes (documented, NOT run by egresswatch)

OpenSnitch is the interactive application firewall half of egresswatch's design:
it attributes every new outbound connection to a process/path and lets you
allow/deny it, surfacing questions like *"why is this `node <hex>.js` connecting
to 23.254.164.123?"* egresswatch's pure-Go `egress` evaluator encodes the same
allow/deny decision model **as data** (`deploy/egress.allow.example.json`) for
the offline/periodic path; OpenSnitch is the live, prompting path.

**egresswatch does not install, start, or configure OpenSnitch.** Every command
below is privileged and changes system state. Review each before running it.

## 1. Install

OpenSnitch ships a daemon + a Qt UI. Install from your distro or upstream
releases (https://github.com/evilsocket/opensnitch/releases):

```sh
# Debian/Ubuntu (release .debs):
sudo apt install ./opensnitch_*.deb ./python3-opensnitch-ui_*.deb
# Arch (AUR): opensnitch + opensnitch-ui
# Fedora: sudo dnf install opensnitch opensnitch-ui
sudo systemctl enable --now opensnitchd
opensnitch-ui &     # the prompt/allow-deny GUI (per-user session)
```

## 2. Prefer the eBPF process-monitor backend

The eBPF backend attributes connections to processes far more reliably than the
proc/ftrace methods (it survives short-lived processes the implant relies on).
It needs a modern kernel with **BTF** (`/sys/kernel/btf/vmlinux` present).

Edit `/etc/opensnitchd/default-config.json`:

```json
{
  "ProcMonitorMethod": "ebpf",
  "DefaultAction": "deny",
  "DefaultDuration": "until restart",
  "InterceptUnknown": false,
  "Firewall": "nftables",
  "LogLevel": 2,
  "Server": { "Address": "unix:///tmp/osui.sock", "LogFile": "/var/log/opensnitchd.log" }
}
```

```sh
sudo systemctl restart opensnitchd
journalctl -u opensnitchd -n 50 --no-pager   # confirm "ebpf" monitor loaded
```

`DefaultAction: deny` is the posture that matches egresswatch's verification
goal — *an allowlist of expected egress; anything else is prompted/denied.*

## 3. Translate the egresswatch allowlist into OpenSnitch rules

`deploy/egress.allow.example.json` is the source of truth for *expected* egress.
Mirror each rule as an OpenSnitch **allow** rule (drop one JSON file per rule in
`/etc/opensnitchd/rules/`), then leave the default action at `deny` so anything
not mirrored prompts. Example for the GitHub rule:

```json
{
  "name": "allow-github",
  "enabled": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "list",
    "operand": "list",
    "list": [
      { "type": "simple", "operand": "dest.port", "data": "443" },
      { "type": "regexp", "operand": "dest.host", "data": "^(github\\.com|.*\\.githubusercontent\\.com)$" }
    ]
  }
}
```

Keep the two views in sync: when you add an entry to `egress.allow.json` (so the
periodic `egresswatch egress` scan stops flagging it), add the matching
OpenSnitch allow rule so the live prompt stops firing too.

## 4. Route denials to the collector

Point OpenSnitch's logging at the same Tailscale collector that receives the
egresswatch JSON reports, so live denials and periodic-scan findings land
together. OpenSnitch can write JSON to a file or a unix socket; ship that with
your existing log forwarder (the suite assumes one local collector over
Tailscale).

## Uninstall

```sh
sudo systemctl disable --now opensnitchd
sudo apt remove opensnitch python3-opensnitch-ui   # or your distro's equivalent
sudo rm -rf /etc/opensnitchd
```
