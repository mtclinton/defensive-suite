# Refinement Plan — defensive-suite Console (manga EDR)

**Scope grounding.** I read the real prototype at `/Users/max/Documents/Claude/Projects/mtclinton/defensive-suite/dashboard/index.html` (507 lines, single static dependency-free file). Be honest about the gap between the brief and the file: the brief describes the *target* (app-shell, sidebar, pinned posture, hero splash, drawer, manga identity); the file is a **page-scrolling vertical document** with **no sidebar, no hero splash, no drawer, and essentially no manga styling**. The correlated C2 detection — supposedly the marquee — is currently *just another critical table row* (`tr.correlated`, lines 97-102, 336-348) distinguished only by a 3px red left-bar and a faint gradient. So this plan is mostly **build the target structure**, not "tone down existing flair." That ordering is itself the most important finding: per Nielsen's iteration data, the biggest wins come from fixing layout/hierarchy catastrophes *before* adding speed-lines.

What's already good and must be **preserved**: the near-black elevation base (`#0a0d13` → panels step lighter, matches the Material dark-elevation guidance), severity-as-pill (dot **+** text label = already dual-channel), the deliberate confidence hue family kept *off* the severity palette (lines 87-92 — this is exactly takeaway visual-a11y #3 done right; don't break it), tabular-nums on numerics, mono reserved for paths/hashes, and the dependency-free single-file constraint.

---

## 1. How to refine (the process)

**The loop (one pass = one of these, in order):**
1. **Heuristic pass first, manga pass last.** Run each refinement pass as a focused heuristic evaluation against Nielsen's 10, but weight the two load-bearing ones for this tool: *Visibility of system status* (can you answer "am I owned right now?" — the posture + hero) and *Aesthetic & minimalist design* (every halftone dot that isn't carrying signal competes with the marquee finding). [refine-process #1]
2. **Plan ≥3 versions (2 iterations) minimum.** v1 fixes catastrophes (no hero, no drawer, page-scroll). v2 polishes hierarchy + adds manga *surgically*. v3 polishes flair + a11y. Expect ~45% gain v1→v2, ~34% v2→v3 — front-loaded, so spend early budget on structure not speed-lines. [refine-process #4]
3. **Verify cold, every pass.** After each version, run a timed glance test: hand a security-minded dev the screen cold and time "find the C2 finding + read the exec→egress chain." Target <10s, one screen, no scroll. Also run grayscale + colorblind sim + a small-text contrast audit. The aesthetic-usability effect will make *you* over-rate it; the cold timer is the antidote. [visual-a11y #8, refine-process #5, info-design #1]
4. **Critique with the ban rule.** Forbid "I like / I don't like." Every comment must finish "...because it speeds/slows triage of the finding." This aesthetic invites pure taste fights; goal-anchoring is the only way to keep flair honest. [refine-process #6]

**How to use the AI design tool well:**
- **Build a reference board first**, don't ask it to invent the synthesis blind. Two precedent sets: (a) real EDR consoles for the kill-chain/triage half — CrowdStrike Falcon process tree, Elastic visual event analyzer, Linear for the focused/keyboard feel; (b) manga editorial layout for the expressive half. Give the tool both and ask it to *reconcile*, not imagine. [refine-process #8]
- **Run multiple AI passes framed as distinct evaluators** (e.g. "you are a SOC analyst," then "you are an accessibility auditor") — that's how a solo dev approximates the 3-5 evaluators that catch ~75% of issues. [refine-process #1]
- **Give it the constraints as hard rails**, not preferences: single file, no deps, one screen no-scroll, severity never color-alone, ≥4.5:1 body text, reserve saturated red for the hero only. Otherwise the tool will paint everything red and add a 1s slide on every widget.

**Token discipline (do this in v1, it's cheap and unblocks everything else):** add a semantic token layer over the existing primitives — `--sev-critical`, `--posture-ok`, `--hero-accent`, `--chrome-halftone` — mapped onto the raw JoJo palette. The palette-switch then becomes a remap of *primitives* while severity *meaning* stays stable, so you never re-audit contrast per theme. Don't over-engineer (no Style Dictionary for n=1). [refine-process #7]

---

## 2. Highest-impact refinements (ranked)

| # | Change | Why (researched principle) | Effort |
|---|--------|----------------------------|--------|
| 1 | **Add the hero "splash" for the correlated C2 finding, top-left, physically dominant.** Promote `tr.correlated` out of the table into a dedicated hero region above the feed. Render it as a directional **exec→egress chain** (process node → egress node) with the **dwell-time between them shown** and the destination 4-tuple. | The temporal sequence *is* the evidence, not decoration; leading tools (Falcon tree, Elastic analyzer) make the marquee a visual time-ordered chain. Eye lands top-left + size = importance; this is the 5-second "am I owned?" answer. [edr-triage #1, info-design #1] | **L** |
| 2 | **Convert to a fixed app-shell: sidebar nav + pinned posture, one screen, no page-scroll.** Replace `.wrap{max-width:1180px;padding…64px}` document flow with a fixed grid (sidebar / posture bar / hero / feed). Move tools, threat-model, architecture-note off the main screen into nav routes. | Three-tier progressive disclosure (hero = critical / feed = mid / drawer = raw) is the core architecture; the no-scroll constraint *is* the best practice, not a limitation. Linear-style opinionated single view beats a configurable grid for one dev. [edr-triage #3, info-design #2 & #8] | **L** |
| 3 | **Add the detail DRAWER on row-click; move all inline lineage/`related` into it.** Today lineage renders inline in the cell (lines 339-341) — that's forensic detail leaking onto the shell. Drawer must be self-sufficient: full cmdline, parent process, egress 4-tuple, file hash + reputation, the correlated counterpart event. | Progressive disclosure / Miller's Law: feed shows verdict + minimal context, raw lives behind the click. Kill "swivel-chair" — the drawer is the flyout; if the operator must leave it to answer "what did it talk to," the design failed. [info-design #2, edr-triage #9] | **M** |
| 4 | **Surface "executed? / contained?" state on the C2 finding (and feed rows).** Add an execution-confirmed flag and a containment overlay — a **"KILLED" impact-stamp** on the chain when the process was terminated. Today this state exists in the backend (the Tauri respond bar) but is invisible on the finding. | The two facts that size the response: did it execute, did the EDR already act. "Ran AND egress succeeded AND not contained" is your true-red. The stamp is both load-bearing and a natural JoJo impact-frame idiom. [edr-triage #4] | **M** |
| 5 | **Make the hero deterministic, not the top-sorted critical row.** Pin to hero only on a hard escalation trigger (correlated exec→egress to unexpected dst). Demote lone signals; sort the feed **recency/escalation-first**, not severity-then-tool (current sort, line 331). | Severity inflation is the #1 trust-killer (88.9% of operators); your user is a dev on his own box — raw technique flags (PowerShell, curl-out) will be wrong constantly. Correlated > lone. "If it's in the hero, it earned it." [edr-triage #5 & #8, info-design #6] | **M** |
| 6 | **Spend the manga ink budget *surgically* on the hero only; keep feed/posture/drawer sober.** Speed-lines = directional flow from exec→egress node (functional, carries the eye). Onomatopoeia = the entity-type / severity headline word ("DODON" as the CRIT callout). Halftone density = a redundant severity channel. Everything quiet stays clean. | Data-ink ratio: decoration on a quiet finding is chartjunk; decoration that makes the live threat unmissable is signal. A calm dark baseline is what *earns* the right to go loud. Quarantine the boldness or the splash stops popping. [info-design #4 & #5, visual-a11y #5 & #8] | **M** |
| 7 | **Add an entity-type badge (Process / Network / File / Host) on every feed item + drawer top.** Make it the loud categorical token (the onomatopoeia slot). | Classification is the first triage move — it tells the operator which mental playbook to load and what evidence to expect. Highest-signal fastest-read token. [edr-triage #2] | **S** |
| 8 | **Keep severity to ~3 saturated steps; desaturate accents for the dark base (~20 sat pts down); spend color budget on chrome, not a 4th alert hue.** Use the screaming red only for the hero display type / onomatopoeia (large text needs just 3:1); pull feed-row severity chips toward muted tones for 12-13px legibility. | Saturated reds "optically vibrate" on dark at small sizes even when contrast math passes; ~3 alert colors max or nothing reads urgent. The palette-switch only works if the baseline is calm. [visual-a11y #2, refine-process #2, info-design #5] | **S** |
| 9 | **Severity gets a redundant non-color channel beyond the existing dot+label: a distinct glyph/shape per tier (filled diamond CRIT, etc.), reusing manga iconography.** | Never color alone — ~8% of men colorblind, red/green is the classic fail, triage is under stress. Manga's iconographic language gives this for free; turns a gimmick into an a11y feature. Verify in grayscale. [edr-triage #7, visual-a11y #3, refine-process #3] | **S** |
| 10 | **Keyboard-first + fast motion: j/k through feed, Enter opens drawer, Esc closes; drawer = quick slide+fade (200-500ms); wrap every decorative effect (speed-lines, onomatopoeia pop, C2 pulse) in `prefers-reduced-motion`.** | Linear's focused feel = keyboard-driven, instant state. Motion sweet spot 200-500ms; a triage tool used under stress must not make you wait on a 1s animation; large movement is a vestibular trigger. [info-design #8, visual-a11y #7] | **S** |
| 11 | **Trim the 6-KPI strip; fold "clean run ✓/✗" into the pinned posture.** Cards for posture, the feed-table for scannable detail, charts only for shape-over-time (e.g. a sparkline of egress volume — never chart a single number). | Match widget to job; data-ink ratio. Six KPIs dilute the posture read. [info-design #4 & #7] | **S** |
| 12 | **Group/collapse N related raw events into one finding-with-count; never merge genuinely distinct detections.** The feed should read as *findings*, not log lines. | Overgrouping is "the more sinister failure mode" (hides a distinct root cause). Your correlated C2 *is* a grouping act — apply the discipline feed-wide. [edr-triage #6] | **M** |

---

## 3. Quick wins vs bigger bets

**Quick wins (do first — high ratio, low risk, mostly within the existing single file):**
- #7 entity-type badge, #8 desaturate accents + cap to 3 steps, #9 redundant severity glyph, #11 trim KPIs into posture — all small CSS/markup edits on the structure that's already there.
- #5's **sort change** (recency/escalation-first, line 331) is a one-line logic swap that immediately improves trust.
- The **semantic token layer** (process §1) — cheap, unblocks the palette-switch and every later contrast audit.
- Wrapping motion in `prefers-reduced-motion` (#10) before you add any motion at all.

**Bigger bets (the structural redesign — this is most of the work, and the brief's "current direction" is aspirational):**
- #2 app-shell conversion (kills page-scroll, adds sidebar/fixed grid) — touches the whole layout.
- #1 hero splash with the directional exec→egress chain + dwell-time + speed-lines — the marquee, where the manga energy concentrates.
- #3 detail drawer + pulling inline lineage behind the click.
- #4 containment/execution state + the "KILLED" stamp (needs the backend exec/contained fields surfaced through the collector contract).
- #12 event grouping (a correlation/render-logic change, not just CSS).

**Sequencing:** quick wins + tokens in v1 alongside the #2 shell skeleton; #1/#3/#4 in v1→v2; #6 manga-ink surgical pass and #12 grouping in v2→v3. Add speed-lines/halftone/onomatopoeia *only after* the hero+feed+drawer hierarchy passes a cold glance test — flair on a broken hierarchy is polish on sand.

---

## 4. What to measure / how to know it's better

**Primary acceptance bar (define "done" up front — a maximalist aesthetic is a polish black hole):**
- **Cold timed glance test:** an unprimed security-minded dev finds the C2 finding *and* reads the exec→egress chain in **<10s**, on **one screen, no scroll**, with **no critical/major issues** in the last test round. When a round surfaces only nitpicks, freeze the structure (ship at ~95%). [refine-process #5 & #9, info-design #1]

**Specific instruments:**
- **5-second "am I owned right now?" test** on the posture + hero alone — pass/fail glanceability. [info-design #1]
- **Grayscale + colorblind-sim screenshot** of the feed: every severity must still be distinguishable (validates #9's redundant channel). [visual-a11y #3]
- **Contrast audit:** body/IOC text ≥4.5:1, large hero display ≥3:1, severity chips/glyphs/focus rings ≥3:1, on every palette in the palette-switch (semantic tokens make this a per-theme remap, not a re-audit). [visual-a11y cross-cutting]
- **Trust / false-positive feel:** over a soak, what fraction of feed items are *actionable*? If the hero ever shows a lone benign technique flag (PowerShell on a dev box), the escalation rule (#5) failed — alert fatigue is a UX failure, not just ops. [edr-triage #5, info-design #6]
- **Swivel-chair check:** can the tester reach a verdict ("what did it talk to, did it run, is it contained") **without leaving the drawer**? If they navigate away, the drawer isn't self-sufficient (#3 failed). [edr-triage #9]
- **Per-iteration usability delta:** track issues-found per cold test across v1→v2→v3; stop when it drops to nitpicks (you've hit the front-loaded diminishing-returns curve). [refine-process #4 & #9]

**Honest trade-off callouts:**
- **Speed-lines help** *only* when they carry the eye exec→egress in the hero; **they hurt** as ambient chrome anywhere else (chartjunk, and they fight small mono data).
- **Onomatopoeia helps** as the inverted-pyramid headline / categorical badge (one loud callout word); **it hurts** if it replaces the plain-language verdict or repeats per-row (then nothing is loud).
- **The saturated manga red helps** as the single hero accent on large type; **it hurts** on 12-13px feed chips (optical vibration) — desaturate there.
- **The aesthetic-usability effect is a real asset** (goodwill, memorability for a tool one person lives in) **and a real trap** (it hides whether a stressed user can actually parse the kill-chain) — which is exactly why every claim above is gated on a *cold, timed, grayscale* test rather than "it looks great."

**Relevant file:** `/Users/max/Documents/Claude/Projects/mtclinton/defensive-suite/dashboard/index.html` — single static dependency-free file; all refinements above must preserve that constraint (no build step, no external deps).