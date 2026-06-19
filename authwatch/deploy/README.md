# authwatch — deployment

authwatch ships these artifacts but **installs nothing automatically**. Every
command below is privileged and changes system state (systemd, auditd). Review
each one before you run it. `authwatch` itself only ever *reads* the system and
*reports*; it does not modify auditd, sysctls, or the kernel.

```
deploy/
├── systemd/authwatch.service          # oneshot, hardened, runs `authwatch check`
├── systemd/authwatch.timer            # daily + on-boot, randomized delay
├── audit/authwatch.rules              # auditd watches for the trust path
├── sigma/lnx_auditd_ld_so_preload_mod.yml   # T1574.006
├── sigma/lnx_auditd_pam_backdoor.yml        # T1556.003
├── config.example.json                # copy to /etc/authwatch/config.json
└── authorized_keys.allow.example      # the attributable-key allowlist format
```

## 1. Install the binary

```sh
make static                                  # builds bin/authwatch (CGO-free, static)
sudo install -m 0755 bin/authwatch /usr/local/bin/authwatch
```

## 2. Configuration (no secrets in source)

```sh
sudo install -d -m 0750 /etc/authwatch
sudo install -m 0640 deploy/config.example.json /etc/authwatch/config.json
sudo install -m 0644 deploy/aide/authwatch.aide.conf /etc/authwatch/authwatch.aide.conf
sudo install -m 0640 deploy/authorized_keys.allow.example /etc/authwatch/authorized_keys.allow

# Webhook auth token comes from the environment, never the config file:
printf 'AUTHWATCH_WEBHOOK_AUTH=Bearer %s\n' "$TOKEN" | sudo tee /etc/authwatch/authwatch.env >/dev/null
sudo chmod 0600 /etc/authwatch/authwatch.env
```

Edit `/etc/authwatch/config.json` so `baseline_path` points at the **off-host**
trust anchor (e.g. an NFS/SSHFS mount that this host can read but not rewrite).

## 3. Capture the off-host baseline (at known-good state)

```sh
sudo authwatch baseline -o /mnt/trust-anchor/authwatch-baseline.json
# Then make the anchor read-only to this host. If the baseline is writable on the
# box, it is worthless.
```

## 4. AIDE database — off-host trust anchor

The service runs `authwatch check --aide`, which checks an AIDE database covering
the trust path (`deploy/aide/authwatch.aide.conf`). Build it at known-good state
and copy it off-host — same trust-anchor rule as the baseline.

```sh
sudo aide --config=/etc/authwatch/authwatch.aide.conf --init       # REVIEW first
sudo cp /var/lib/aide/aide.db.new.gz /mnt/trust-anchor/aide.db.gz   # read-only anchor
```

## 5. systemd timer  — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/authwatch.service /etc/systemd/system/authwatch.service
sudo install -m 0644 deploy/systemd/authwatch.timer   /etc/systemd/system/authwatch.timer
sudo systemctl daemon-reload
sudo systemctl enable --now authwatch.timer
# Smoke-test one run and read the journal:
sudo systemctl start authwatch.service
journalctl -u authwatch.service -n 50 --no-pager
```

## 6. auditd watches  — REVIEW BEFORE RUNNING (changes auditd config)

These persist the trust-path watches so `authwatch check` reports green for the
auditd visibility check. Loading audit rules modifies kernel audit state.

```sh
sudo install -m 0640 deploy/audit/authwatch.rules /etc/audit/rules.d/authwatch.rules
sudo augenrules --load          # compile + load all rules.d files
sudo auditctl -l | grep authwatch_   # confirm the watches are active
```

## 7. Sigma rules

Convert with `sigma` / `pySigma` for your SIEM, or feed the auditd events
(filtered by the `authwatch_*` keys) to a backend that ingests Sigma directly.

```sh
sigma convert -t <backend> deploy/sigma/lnx_auditd_ld_so_preload_mod.yml
sigma convert -t <backend> deploy/sigma/lnx_auditd_pam_backdoor.yml
```

## Uninstall

```sh
sudo systemctl disable --now authwatch.timer
sudo rm -f /etc/systemd/system/authwatch.{service,timer} && sudo systemctl daemon-reload
sudo rm -f /etc/audit/rules.d/authwatch.rules && sudo augenrules --load
sudo rm -rf /etc/authwatch /usr/local/bin/authwatch
```
