# console — self-update & signing enablement

> ⚠️ **THE UPDATER IS INERT UNTIL YOU COMPLETE KEYGEN.** The committed
> `tauri.conf.json` ships a clearly-marked **PLACEHOLDER** updater public key and
> `bundle.createUpdaterArtifacts = false`. With those defaults the console builds
> and runs normally but **never** finds, downloads, or installs an update — every
> check fails closed (offline / placeholder-key / no manifest are all swallowed,
> no panic, no nag loop). Nothing here is run by the build, the tests, or CI's
> dry-run. **Read before running.**

## What "self-update" is here

The console uses the **Tauri v2 updater plugin** (desktop only). On launch it does
**one** silent check and, if a newer **signature-verified** build exists, fires a
single native notification — *"Console update `<version>` available"* — in the same
style as the posture poller. It **never auto-installs**. The UI drives the actual
update via two Rust commands:

| Command | What it does |
|---------|--------------|
| `check_update`   | Asks the endpoint whether a newer signed build exists; returns `{available, current_version, version}`. Never installs. |
| `install_update` | Downloads + **signature-verifies** + installs the newer build, then relaunches. Only ever called explicitly. |

The update flow is **gated by a signature**: the downloaded AppImage is verified
against the committed updater **public** key before it is applied. A bad or absent
signature fails the install rather than running anything. This is the updater
signature — it is **separate** from OS code-signing (see the last section).

### Wiring (already in the repo)

| Piece | Where |
|-------|-------|
| Cargo dep `tauri-plugin-updater = "2"` (desktop targets) | `console/src-tauri/Cargo.toml` |
| `plugins.updater.{endpoints, pubkey}` + `bundle.createUpdaterArtifacts: false` | `console/src-tauri/tauri.conf.json` |
| Capability permission `updater:default` | `console/src-tauri/capabilities/default.json` |
| Plugin registration + launch check + `check_update`/`install_update` commands | `console/src-tauri/src/main.rs` |
| Secret-gated signing + `latest.json` generation | `.github/workflows/release.yml` |
| Keypair generation | `make console-keygen` |

The endpoint the console polls is the static manifest on the **latest** GitHub
release:

```
https://github.com/mtclinton/defensive-suite/releases/latest/download/latest.json
```

## Enablement runbook (operator-only)

### 1. Generate the updater keypair (PRIVATE key NEVER goes in the repo)

```sh
make console-keygen
# ↳ runs: cd console/src-tauri && cargo tauri signer generate -w ~/.tauri/defensive-suite-updater.key
#   (needs the Tauri CLI: cargo install tauri-cli --version '^2')
```

This prints a **PUBLIC** key and writes the **PRIVATE** key to
`~/.tauri/defensive-suite-updater.key` (protected by a password you set). The
private key + password are **yours** — they never enter this repository, the
build, or any committed file.

### 2. Paste the PUBLIC key into the config

Replace the placeholder in `console/src-tauri/tauri.conf.json`:

```jsonc
"plugins": {
  "updater": {
    "endpoints": ["https://github.com/mtclinton/defensive-suite/releases/latest/download/latest.json"],
    "pubkey": "<PASTE THE PRINTED PUBLIC KEY HERE>"   // was the PLACEHOLDER
  }
}
```

The public key is **safe to commit** — it only verifies signatures, it cannot
create them. Commit this change.

### 3. Add the PRIVATE key + password as GitHub Actions secrets

In the repo's **Settings → Secrets and variables → Actions**, add:

| Secret | Value |
|--------|-------|
| `TAURI_SIGNING_PRIVATE_KEY`          | the **contents** of `~/.tauri/defensive-suite-updater.key` |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | the password you set during keygen |

> ⚠️ Add them as **secrets**, never as plaintext in the workflow or repo. The
> release job maps them to env; on forks and the `workflow_dispatch` dry-run they
> are absent, and the build falls through to the unsigned path (stays green).

### 4. createUpdaterArtifacts — handled for you on release

You do **not** need to flip `createUpdaterArtifacts` in the committed config. The
release job (step below) enables it **at build time** only when the signing secret
is present:

```yaml
# .github/workflows/release.yml — the gate (secrets → env, NOT a job-level `if`):
if [ -n "$TAURI_SIGNING_PRIVATE_KEY" ]; then
  cargo tauri build --bundles appimage --config '{"bundle":{"createUpdaterArtifacts":true}}'
else
  cargo tauri build --bundles appimage      # unchanged unsigned path (dry-run / forks)
fi
```

To build a **signed** AppImage **locally**, export the same env and pass the same
`--config` (or set `createUpdaterArtifacts: true` in the config):

```sh
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/defensive-suite-updater.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="<the password>"
cd console
cargo tauri build --bundles appimage --config '{"bundle":{"createUpdaterArtifacts":true}}'
# Tauri writes <name>.AppImage and the detached <name>.AppImage.sig next to it.
```

## How `latest.json` is published

On a **tag push** (`v*`), when the signing secret is present, the release job:

1. Builds the AppImage with `createUpdaterArtifacts` → Tauri emits the AppImage
   **and** a detached `…AppImage.sig`.
2. Generates the static manifest `latest.json` from the tag + signature + the
   release download URL.
3. Publishes the signed AppImage, its `.sig`, and `latest.json` to the GitHub
   Release. Because the manifest keeps the name `latest.json`, the console's
   `releases/latest/download/latest.json` endpoint resolves to the newest tag.

The manifest shape (Tauri's static-manifest schema):

```json
{
  "version": "v1.2.3",
  "notes": "defensive-suite console v1.2.3",
  "pub_date": "2026-01-01T00:00:00Z",
  "platforms": {
    "linux-x86_64": {
      "signature": "<contents of the .AppImage.sig>",
      "url": "https://github.com/mtclinton/defensive-suite/releases/download/v1.2.3/defensive-suite-console-v1.2.3-amd64.AppImage"
    }
  }
}
```

> When the secret is **absent** (dry-run, forks): no `.sig`, **no `latest.json`**,
> and the release carries the same unsigned AppImage as before. The build stays
> green — updater-artifact creation + signing are fully gated on the secret.

Add more `platforms` entries (`darwin-aarch64`, `darwin-x86_64`, `windows-x86_64`)
as you build + sign those targets; the console reads its own platform key.

## How a client checks / installs

1. **On launch:** one silent check; a notification appears if a newer signed build
   is available. No prompt is forced, nothing installs.
2. **On demand from the UI:**
   - call `check_update` → shows whether an update exists and which version;
   - call `install_update` → downloads, signature-verifies, installs, relaunches.

If the endpoint is unreachable, the manifest is missing, or the pubkey is still
the placeholder, the check returns "no update" / an error string — the console
behaves exactly as it did before the updater existed.

---

## OS code-signing (operator-provides-certs — SEPARATE from the updater signature)

The updater signature above (minisign/Tauri keypair) authenticates the **update
payload**. It is **not** OS code-signing. macOS Gatekeeper and Windows SmartScreen
require **paid, operator-owned certificates** that are **never** stored in this
repo — supply them as CI secrets, exactly like the updater private key. These are
optional and orthogonal to the updater; skip them and self-update still works on
Linux (AppImage needs no OS code-signing).

### macOS — Apple Developer ID + notarization

Requires a paid **Apple Developer Program** membership and a **Developer ID
Application** certificate. Tauri reads these env vars during `cargo tauri build`
(set them from CI **secrets**, never in the workflow text):

| Env var | Meaning |
|---------|---------|
| `APPLE_CERTIFICATE`          | base64 of the exported `.p12` (Developer ID Application cert + key) |
| `APPLE_CERTIFICATE_PASSWORD` | the `.p12` export password |
| `APPLE_SIGNING_IDENTITY`     | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_ID`                   | your Apple ID email (for notarytool) |
| `APPLE_PASSWORD`             | an **app-specific password** for that Apple ID |
| `APPLE_TEAM_ID`              | your 10-char Team ID |

With those set, Tauri code-signs the `.app`/`.dmg` and submits it to Apple's
**notarytool**, then staples the ticket. (Build the macOS targets on a macOS
runner; add the corresponding `darwin-*` entries to `latest.json`.)

### Windows — Authenticode

Requires a paid **Authenticode code-signing certificate** (OV, or EV via an HSM).
Configure Tauri's `bundle.windows` signing in `tauri.conf.json` and supply the
cert material from CI **secrets**:

- `bundle.windows.certificateThumbprint` — the installed cert's thumbprint, **or**
- a software cert imported at build time (e.g. `signtool`/`certutil` from a
  base64 `WINDOWS_CERTIFICATE` + `WINDOWS_CERTIFICATE_PASSWORD` secret), with
  `bundle.windows.{digestAlgorithm: "sha256", timestampUrl: "<your RFC-3161 TSA>"}`.

EV certs live on a hardware token / cloud HSM — wire the vendor's signing tool via
`bundle.windows.signCommand`. Add a `windows-x86_64` entry to `latest.json` for
the signed installer/MSI.

> Both macOS and Windows code-signing need **paid certs you own** and are entirely
> separate from the updater signature. None of this cert material may be committed
> to the repo or printed — supply it only as CI secrets.
