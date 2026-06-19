# Setup

## 1. Configure Claude Code attribution off (once, globally)

So nothing in any repo advertises the toolchain. Add to `~/.claude/settings.json`:

```json
{
  "attribution": {
    "commit": "",
    "pr": ""
  }
}
```

(`includeCoAuthoredBy` still works but is deprecated and can conflict with `attribution` —
use `attribution`.) This only affects commits/PRs made after you set it.

## 2. Initialize and push to mtclinton

```sh
cd defensive-suite
git init
git add .
git commit -m "Initial scaffold: defensive suite for Linux workstation threat model"
gh repo create mtclinton/defensive-suite --private --source=. --push
```

By default `.gitignore` excludes `CLAUDE.md` and `.claude/` so the public repo carries no
tool tells. Remove those two lines from `.gitignore` if you'd rather keep `CLAUDE.md`
tracked (it's common and is config, not authorship credit).

## 3. Build, one tool at a time

```sh
cd authwatch
claude
# > Build this tool per ./DESIGN.md.
```

Recommended order: `authwatch` + `credsentinel` → `instguard` → `posturescan`
→ `egresswatch` → `bpfsentry`.

## 4. Add a LICENSE

Your choice before publishing. Note: calling OSS tools (AIDE, OpenSnitch, Tetragon, Lynis,
Volatility 3) as separate binaries carries no obligation; vendoring/forking their code —
especially Volatility 3's GPL eBPF plugins — pulls in their licenses.