# posturescan — deployment

posturescan ships these artifacts but **installs nothing automatically**.
posturescan itself only ever *reads* the system and *reports*; it never writes to
`/etc`, changes a sysctl, or applies remediation. The privileged commands below
change system state — review each one before you run it.

```
deploy/
├── systemd/posturescan.service          # oneshot, hardened, runs `posturescan scan`
├── systemd/posturescan.timer            # daily + on-boot, randomized delay
├── profiles/hardening-target.conf       # the target sysctl profile (data)
├── sysctl.d/99-posturescan.conf.example # what `remediate` generates (ARTIFACT, not installed)
└── config.example.json                  # copy to /etc/posturescan/config.json
```

## 1. Install the binary

```sh
make static                                     # builds bin/posturescan (CGO-free, static)
sudo install -m 0755 bin/posturescan /usr/local/bin/posturescan
```

## 2. Configuration (no secrets in source)

```sh
sudo install -d -m 0750 /etc/posturescan
sudo install -m 0640 deploy/config.example.json        /etc/posturescan/config.json
sudo install -m 0644 deploy/profiles/hardening-target.conf /etc/posturescan/hardening-target.conf

# Webhook auth token comes from the environment, never the config file:
printf 'POSTURESCAN_WEBHOOK_AUTH=Bearer %s\n' "$TOKEN" | sudo tee /etc/posturescan/posturescan.env >/dev/null
sudo chmod 0600 /etc/posturescan/posturescan.env
```

## 3. Run a scan (read-only — safe)

```sh
posturescan scan                       # OK/DIFFERENT table + hardening index → stdout
posturescan scan --format json         # machine-readable report
posturescan scan --wrap-tools          # also run lynis / oscap / systemd-analyze
posturescan scan --spec ./config.json  # also audit + score a container spec
```

## 4. See the remediation (DRY RUN — applies nothing)

```sh
posturescan remediate                  # prints the /etc/sysctl.d drop-in + commands
```

`remediate` **never** writes the drop-in or runs `sysctl`. It prints the exact
file content and the privileged commands (`sudo install ... /etc/sysctl.d/99-posturescan.conf`,
`sudo sysctl --system`) for you to review and run yourself. `deploy/sysctl.d/99-posturescan.conf.example`
is a sample of that generated output, shipped as an artifact — it is **not**
installed into `/etc/sysctl.d/`.

Kernel lockdown and module-signature enforcement are boot-time settings, not
runtime sysctls — `remediate` emits a kernel-cmdline note for them instead of a
drop-in line:

```
lockdown=confidentiality module.sig_enforce=1   # add to GRUB_CMDLINE_LINUX, then update-grub/grub2-mkconfig
```

## 5. systemd timer — REVIEW BEFORE RUNNING (changes system state)

```sh
sudo install -m 0644 deploy/systemd/posturescan.service /etc/systemd/system/posturescan.service
sudo install -m 0644 deploy/systemd/posturescan.timer   /etc/systemd/system/posturescan.timer
sudo systemctl daemon-reload
sudo systemctl enable --now posturescan.timer
# Smoke-test one run and read the journal:
sudo systemctl start posturescan.service
journalctl -u posturescan.service -n 50 --no-pager
```

## Uninstall

```sh
sudo systemctl disable --now posturescan.timer
sudo rm -f /etc/systemd/system/posturescan.{service,timer} && sudo systemctl daemon-reload
sudo rm -rf /etc/posturescan /usr/local/bin/posturescan
```
