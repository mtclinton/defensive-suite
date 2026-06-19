# egresswatch — deployment

egresswatch ships these artifacts but **installs nothing automatically**. Every
command below is privileged and/or changes system state (systemd, eBPF, Falco,
Suricata, Zeek, OpenSnitch). Review each one before you run it. `egresswatch`
itself, in its default build, only ever *reads* /proc and *reports*; it does not
modify sysctls, load eBPF, or change the kernel.

```
deploy/
├── systemd/egresswatch.service          # oneshot, hardened, runs `egresswatch scan`
├── systemd/egresswatch.timer            # every 15 min + on-boot, randomized delay
├── config.example.json                  # copy to /etc/egresswatch/config.json
├── egress.allow.example.json            # the expected-egress allowlist format
├── falco/egresswatch_magic_packet.yaml  # Falco: setsockopt+SO_ATTACH_FILTER (T1205.002)
├── suricata/egresswatch-bpfdoor.rules   # Suricata: magic seq 1234 + invalid ICMP code 1
├── zeek/egresswatch-bpfdoor.zeek        # Zeek: same two BPFDoor markers
└── opensnitch/README.md                 # OpenSnitch install-and-configure notes (documented)
```

The eBPF magic-packet sensor source + bpf2go directive + loader live one level up
in [`../bpf/`](../bpf/), all behind the `linux && ebpf` build tag (excluded from
the default build). Its build+load commands are in section 5 below.

## 1. Install the binary

```sh
make static                                  # builds bin/egresswatch (CGO-free, static)
sudo install -m 0755 bin/egresswatch /usr/local/bin/egresswatch
```

## 2. Configuration (no secrets in source)

```sh
sudo install -d -m 0750 /etc/egresswatch
sudo install -m 0640 deploy/config.example.json /etc/egresswatch/config.json
sudo install -m 0640 deploy/egress.allow.example.json /etc/egresswatch/egress.allow.json

# Webhook auth token comes from the environment, never the config file:
printf 'EGRESSWATCH_WEBHOOK_AUTH=Bearer %s\n' "$TOKEN" | sudo tee /etc/egresswatch/egresswatch.env >/dev/null
sudo chmod 0600 /etc/egresswatch/egresswatch.env
```

Edit `/etc/egresswatch/egress.allow.json` to match your workstation's expected
egress (package mirrors, Tailscale CGNAT 100.64.0.0/10, GitHub, DNS/NTP). Pre-
resolve hostnames into `resolved_ips` so the evaluator stays pure and offline.

## 3. Smoke-test the scan (reads only; safe to run anytime)

```sh
# BPFDoor/Symbiote triage + egress-allowlist evaluation over the live /proc:
sudo egresswatch scan --config /etc/egresswatch/config.json --no-webhook
# Just the triage, or just the egress half:
sudo egresswatch triage --no-webhook
egresswatch egress --allowlist /etc/egresswatch/egress.allow.json --no-webhook
# Over an offline /proc snapshot (e.g. a forensic mount) instead of the live one:
egresswatch triage --proc /mnt/snapshot/proc --no-webhook
```

Exit 0 = clean (no findings at medium or above). The /proc triage cannot read
whether a BPF filter is attached, so it flags raw AF_PACKET (SOCK_RAW) sockets
and escalates one to Critical only when corroborated by another marker (deleted
exe, packet_recvmsg block, or a known zero-byte mutex). **Zero corroborated
raw-socket processes = no BPFDoor-class implant in the /proc surface** — the
design's verification statement. The eBPF magic-packet sensor (section 5)
confirms an actual attached filter.

## 4. systemd timer — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/egresswatch.service /etc/systemd/system/egresswatch.service
sudo install -m 0644 deploy/systemd/egresswatch.timer   /etc/systemd/system/egresswatch.timer
sudo systemctl daemon-reload
sudo systemctl enable --now egresswatch.timer
sudo systemctl start egresswatch.service          # one immediate run
journalctl -u egresswatch.service -n 50 --no-pager
```

## 5. eBPF magic-packet sensor — REVIEW; loads eBPF into the kernel

The sensor (`../bpf/magicpacket.bpf.c` + loader) fires the instant a process
attaches a CBPF filter to a socket — the BPFDoor signature — instead of waiting
for the next periodic scan. It is **not** in the default binary; it is behind the
`ebpf` build tag and needs clang + libbpf headers + a BTF-enabled kernel.
egresswatch never compiles or loads it for you. To build it yourself:

```sh
# one-time: generate vmlinux.h from the running kernel's BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
# install the bindings generator and produce magicpacket_bpfel.go + .o (clang)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go generate ./bpf/...
# build the eBPF-enabled binary (pulls in cilium/ebpf, hence not the default)
CGO_ENABLED=0 go build -tags ebpf -o bin/egresswatch-ebpf .
# load + attach the tracepoint (needs CAP_BPF/CAP_SYS_ADMIN):
sudo ./bin/egresswatch-ebpf sensor --config /etc/egresswatch/config.json
```

In the default (no-tag) binary, `egresswatch sensor` prints these instructions
and exits non-zero rather than doing anything.

## 6. Falco rule — REVIEW; loads into your Falco deployment

```sh
sudo install -m 0640 deploy/falco/egresswatch_magic_packet.yaml /etc/falco/rules.d/egresswatch_magic_packet.yaml
sudo systemctl restart falco          # or falco-modern-bpf / falcoctl, per your setup
journalctl -u falco -n 50 --no-pager  # confirm the rule loaded without errors
```

Tune the `known_cbpf_users` list to your host's legitimate packet sniffers
(dhclient, tcpdump, …) — the BPFDoor value is in what is *not* on that list.

## 7. Suricata / Zeek rules — REVIEW; gateway tap/mirror sensor

These run on a mirrored/tap interface at the homelab gateway (not on the
workstation). They catch the on-wire BPFDoor markers even when a kernel-resident
implant hides its socket from the live host.

```sh
# Suricata
sudo install -m 0644 deploy/suricata/egresswatch-bpfdoor.rules /etc/suricata/rules/egresswatch-bpfdoor.rules
#   add to suricata.yaml rule-files, then:
sudo suricata-update  &&  sudo systemctl restart suricata
sudo suricata -T -c /etc/suricata/suricata.yaml   # validate config + rules first

# Zeek
sudo install -m 0644 deploy/zeek/egresswatch-bpfdoor.zeek /opt/zeek/share/zeek/site/egresswatch-bpfdoor.zeek
echo '@load ./egresswatch-bpfdoor' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
sudo zeekctl deploy
```

The SIDs use the local `1000010`, `1000012`, `1000013` range — adjust to your
numbering scheme so they don't collide with other local rules.

## 8. OpenSnitch — the live application-firewall path

See [`opensnitch/README.md`](opensnitch/README.md). egresswatch does not install
or configure OpenSnitch; the notes show how to install it, enable the eBPF
process-monitor backend, set `DefaultAction: deny`, and mirror the
`egress.allow.json` rules as OpenSnitch allow rules so live prompts and the
periodic scan stay in sync.

## Uninstall

```sh
sudo systemctl disable --now egresswatch.timer
sudo rm -f /etc/systemd/system/egresswatch.{service,timer} && sudo systemctl daemon-reload
sudo rm -f /etc/falco/rules.d/egresswatch_magic_packet.yaml && sudo systemctl restart falco
sudo rm -f /etc/suricata/rules/egresswatch-bpfdoor.rules
sudo rm -f /opt/zeek/share/zeek/site/egresswatch-bpfdoor.zeek   # and the @load line
sudo rm -rf /etc/egresswatch /usr/local/bin/egresswatch
# Remove the eBPF sensor by stopping the `egresswatch-ebpf sensor` process; it
# detaches the tracepoint on exit (nothing persists in the kernel).
```
