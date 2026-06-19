# instguard — deployment

instguard ships these artifacts but **installs nothing automatically**. Every
privileged command below changes system state (systemd) — review each before you
run it. instguard itself only ever *reads* project files and *queries OSV.dev*;
it never installs, builds, or executes any npm package or AUR build script.

```
deploy/
├── systemd/instguard.service              # oneshot, hardened, runs `instguard check`
├── systemd/instguard.timer                # every 6h + on-boot, randomized delay
├── ci/instguard-gate.sh                   # CI / pre-commit BLOCK gate
├── ci/pre-commit-config.example.yaml      # pre-commit.com hook wiring
├── sigma/lnx_npm_malicious_install_hook.yml  # T1195.002 / T1059.004
├── config.example.json                    # copy to /etc/instguard/config.json
└── release-meta.example.json              # publish-date input for the cooldown
```

## The safe install workflow (documented — instguard does NOT run these)

instguard is the *vetting* step in a deliberately script-free install. The flow
the design mandates, which you run yourself:

```sh
npm ci --ignore-scripts          # install against the committed lock, scripts OFF
instguard check --project .      # vet drift / hooks / MAL- advisories / AUR
npm audit signatures             # require SLSA provenance / publish attestations
# only if you must enable a vetted package's scripts, a deliberate second pass:
npm rebuild <pkg>                # runs install scripts for packages you trust
```

Never run a bare `npm install` (it executes every lifecycle script before you
have looked at anything). The npm `--min-release-age=3` flag (npm CLI ≥ 11.10.0)
complements instguard's cooldown, but note its caveats: `npx`/`bunx` ignore it,
and it only affects *new* resolution, not versions already pinned in the lock —
which is exactly why instguard re-checks the pinned set.

For AUR, build PKGBUILDs inside a sandbox so a hook cannot reach `$HOME` or the
network even if instguard misses something:

```sh
firejail --net=none --private -- makepkg -si       # or:
systemd-nspawn ... makepkg                          # ephemeral container
```

## 1. Install the binary

```sh
make static                                  # builds bin/instguard (CGO-free, static)
sudo install -m 0755 bin/instguard /usr/local/bin/instguard
```

## 2. Configuration (no secrets in source)

```sh
sudo install -d -m 0750 /etc/instguard
sudo install -m 0640 deploy/config.example.json /etc/instguard/config.json
# Point project_dir at the repo to scan; mount it read-only to the service.

# Webhook auth token comes from the environment, never the config file:
printf 'INSTGUARD_WEBHOOK_AUTH=Bearer %s\n' "$TOKEN" | sudo tee /etc/instguard/instguard.env >/dev/null
sudo chmod 0600 /etc/instguard/instguard.env
```

Environment overrides (all win over the file):

| Env | Meaning |
|-----|---------|
| `INSTGUARD_WEBHOOK_URL` | collector webhook endpoint |
| `INSTGUARD_WEBHOOK_AUTH` | `Authorization` header value (e.g. `Bearer …`) |
| `INSTGUARD_PROJECT_DIR` | project directory to scan |
| `INSTGUARD_OSV_URL` | OSV.dev query endpoint (or a mirror) |
| `INSTGUARD_COOLDOWN_DAYS` | release-age cooldown in days (default 3) |
| `INSTGUARD_NPM_LOGS_DIR` | npm logs dir for `instguard audit` |
| `INSTGUARD_OFFLINE_OSV` | `1` to skip the OSV network query |

## 3. CI / pre-commit gate

```sh
# CI step (fails the pipeline on a BLOCK verdict):
sh deploy/ci/instguard-gate.sh .

# Air-gapped CI still runs every static check:
INSTGUARD_OFFLINE_OSV=1 sh deploy/ci/instguard-gate.sh .

# Or wire it as a pre-commit hook:
cat deploy/ci/pre-commit-config.example.yaml   # merge into .pre-commit-config.yaml
```

## 4. systemd timer — REVIEW BEFORE RUNNING (changes system state)

The timer runs a periodic scan of the configured project and reports verdicts to
the collector. The unit is hardened to a read-only audit (`DynamicUser`,
`ProtectSystem=strict`, project mounted `ReadOnlyPaths`). Edit `ReadOnlyPaths=`
and `project_dir` to your project path first.

```sh
sudo install -m 0644 deploy/systemd/instguard.service /etc/systemd/system/instguard.service
sudo install -m 0644 deploy/systemd/instguard.timer   /etc/systemd/system/instguard.timer
sudo systemctl daemon-reload
sudo systemctl enable --now instguard.timer
# Smoke-test one run and read the journal:
sudo systemctl start instguard.service
journalctl -u instguard.service -n 50 --no-pager
```

## 5. Release-age cooldown metadata (optional)

The cooldown compares each pinned version's publish date against `now` with a
pure function, so it needs no registry access. Supply the dates as a JSON map:

```sh
instguard check --project . --release-meta deploy/release-meta.example.json
```

Generate the map from `npm view <pkg> time` or your mirror's metadata.

## 6. Post-install audit

After any install that may have run scripts, audit npm's logs for hooks that
executed:

```sh
instguard audit                       # scans ~/.npm/_logs
instguard audit --logs /path/_logs    # or a specific log dir
```

## 7. Sigma rule

Convert with `sigma` / `pySigma` for your SIEM to catch the install-hook RCE
pattern at runtime (complements the static `check`):

```sh
sigma convert -t <backend> deploy/sigma/lnx_npm_malicious_install_hook.yml
```

## Uninstall

```sh
sudo systemctl disable --now instguard.timer
sudo rm -f /etc/systemd/system/instguard.{service,timer} && sudo systemctl daemon-reload
sudo rm -rf /etc/instguard /usr/local/bin/instguard
```
