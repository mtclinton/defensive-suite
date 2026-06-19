# instguard — DESIGN

**Threats:** Mastra/easy-day-js, IronWorm, Miasma/Shai-Hulud, codexui-android, Nx Console,
TrapDoor, and the AUR atomic-lockfile cross-registry hop.

## What it does

Intercepts the moment of maximum risk — `npm install` / `pip install` / AUR build —
because these incidents almost all execute at install time, before any `import`:

1. Diff `package.json` against the lockfile to catch a dependency present in one but not
   the other (the gap a payload lives in).
2. Grep install hooks (`preinstall` / `postinstall` / `prepare`) for `curl|sh`, `node -e`,
   base64/atob blobs, and TLS-disabling (`NODE_TLS_REJECT_UNAUTHORIZED=0`).
3. Query the OSV.dev API for `MAL-` advisories on every pinned version.
4. Enforce a release-age cooldown.
5. For AUR, parse `PKGBUILD` / `.install` / `.hook` for unexpected `npm`/`bun`/`npx`/`pnpm`
   invocations; de-obfuscate hex/quoting tricks **as data**, never executing.

## Build

- **Language:** Go (or TypeScript) CLI.
- **Default workflow:** `npm ci --ignore-scripts` (never bare `npm install`), then run
  `instguard` to vet scripts before a second pass enables them.
- **Cooldown:** `npm --min-release-age=3` (days; npm CLI ≥ 11.10.0, Feb 2026). Most
  malicious packages get a `MAL-` classification within ~3 days.
  - Caveats: `npx`/`bunx` do **not** honor these flags; cooldown only affects new
    resolution, not versions already pinned in `package-lock.json`.
- **Provenance:** `npm audit signatures` — require SLSA attestations. This alone would
  have rejected the entire Mastra wave (pushed from a plain token, no attestations).
- **Build on / learn from:** OSV-Scanner, lockfile-lint, `atomic-arch-check` (AUR layer).
- **AUR:** yay 13.0 PKGBUILD-age display + `AURPreInstall` hooks, or build PKGBUILDs
  inside `firejail --net=none --private` / `systemd-nspawn` so a hook can't reach `$HOME`
  or the network.

## What it verifies

Pre-install verdict (`SAFE` / `REVIEW` / `BLOCK`) per package with the reason, plus a
post-install audit of `~/.npm/_logs` for any postinstall that ran. Exit 1 fails CI.

## Effort

Weekend for the npm/lockfile/OSV core; AUR de-obfuscation + sandbox wiring is a second weekend.