# DC-Assessor: Application Plan

Companion to [dc-assessor-plan.md](dc-assessor-plan.md), which defines *what* is checked. This document defines the application people install and use: its shape, install and run steps, screens, and visual design.

**Status:** Plan only. No code yet.

---

## 1. What the user asked for

- Lightweight, installed on-prem, easy to run, with a few simple steps.
- Beautiful and colorful, but with a **limited palette**. Suggested direction: the Claude app color theme and fonts.
- **Original icons** (real Windows and Microsoft icons), not drawn or improvised ones.
- **No dummy data and no decorative status gimmicks.** No "Live", "Active", "Running", pulsing dots or invented numbers. Everything on screen comes from a real assessment or real progress.
- **Not card-oriented.** Content is shown in tables, lists and panes, not grids of tiles.

---

## 2. Application shape

### Recommendation: one small Windows desktop app, with a built-in command line

| Part | Technology | Why |
|---|---|---|
| App shell | **Tauri 2** (Rust) | Produces a small installer (target under 25 MB) that uses the WebView2 engine already present on Windows, instead of bundling a browser like Electron does (150 MB+). No background service, no database server, no web server, no open ports. |
| User interface | **Svelte 5 + TypeScript** | Fast and small. The same UI code is reused for the offline HTML export, so the exported report looks exactly like the app. |
| On-prem collectors | **PowerShell scripts** shipped inside the app, run with the Windows PowerShell 5.1 that is built into every Windows machine | Nothing extra to install on servers. The same scripts can run alone on a Domain Controller or Server Core where there is no GUI. |
| Cloud collectors | **Rust**, inside the app | Better control of Microsoft Graph paging, retries and throttling. |
| Analysis engine | **Rust**, inside the app | Fast enough for 500k-object domains and the attack-path graph. Analysis needs no network and no admin rights. |
| Storage | Plain files in a folder: one telemetry bundle (.zip), one `results.json`, and one SQLite index file per assessment | Easy to copy, archive, delete, or hand to someone else. The SQLite file is an embedded index for instant search (no database server) and can be rebuilt from the bundle. |
| PDF export | WebView2's built-in print-to-PDF | No extra PDF engine to ship. |
| Excel export | `rust_xlsxwriter` | No Office needed. |

The same `DCAssessor.exe` also works as a command-line tool:

```
DCAssessor.exe collect  --scope contoso.com --tenant contoso.onmicrosoft.com --out D:\Assessments
DCAssessor.exe analyze  --bundle D:\Assessments\contoso-2026-10-05.zip
DCAssessor.exe export   --results ...\results.json --format pdf,xlsx,html
```

This supersedes decisions 1 and 2 in the main plan. Collectors stay in PowerShell, the engine moves into the app, and the dashboard becomes the app itself plus an offline HTML export. If you'd rather keep everything in PowerShell, the app shell still works; only the engine changes.

### Requirements on the machine that runs it

- Windows 10/11 or Windows Server 2016 and newer, 64-bit.
- WebView2 runtime. It is already built into Windows 11 and Server 2025, and present on most updated Windows 10 machines. For Server 2016/2019/2022 the installer includes the offline WebView2 installer and adds it only if it is missing.
- Windows PowerShell 5.1 (built in).
- Recommended place to run: a domain-joined admin workstation or PAW. Running on a DC is supported through the CLI, but not required.

### Install options

1. **MSI installer** (per-machine, signed), for teams that deploy software centrally.
2. **Portable ZIP** (unzip and run), for consultants and locked-down environments. It writes nothing outside its own folder and the chosen assessments folder.

Uninstall removes the app completely. Assessment data is kept unless the user chooses to delete it.

### What the app never does

- It never writes to AD, Entra ID, Microsoft 365, Azure, or endpoints. (The read-only guard from the main plan applies to every collector.)
- It never phones home, sends telemetry about itself, or loads anything from the internet. The only outbound connections are the ones the user asks for: Microsoft Graph, Exchange/Teams/SharePoint endpoints, and Azure Resource Manager.
- It does not store credentials. Cloud sign-in uses the standard Microsoft sign-in window (interactive or device code) and tokens stay in memory for the session.

---

## 3. Run steps (what the user does)

The whole flow is five steps, shown as a numbered left-to-right step bar at the top of the "New assessment" screen:

1. **Scope.** Pick the forest/domains (detected automatically from the machine's domain) and, optionally, sign in to the Microsoft 365 tenant. Select areas: on-prem AD, Entra ID, Microsoft 365, Azure, endpoints, baselines, threat hunting. Each area shows what it needs.
2. **Check access.** The app tests what the current account can actually read, before collecting anything. Results are per area: *Can assess*, *Partly (reason)*, or *Cannot assess (reason, how to fix)*. This is the real result of real test queries, not an estimate.
3. **Collect.** Collection runs with honest progress. Each collector is listed with its actual state (waiting, in progress, done, skipped, failed), the number of objects read so far, elapsed time, and any errors as they happen. Nothing animates unless real work is happening, and no fake percentages are shown: a percentage appears only where the total is known, such as "12,408 of 48,000 users".
4. **Review.** The results workspace opens automatically once analysis finishes.
5. **Export.** Executive PDF, technical PDF/HTML, XLSX remediation plan, CSV/JSON/SARIF, or the offline HTML dashboard.

Opening a previous assessment or a bundle collected elsewhere (for example, by the CLI on a DC) skips straight to step 4.

---

## 4. Screens

### Layout model: familiar to AD administrators, not a card grid

The workspace follows the three-pane layout AD admins already know from MMC consoles (ADUC, GPMC) and Windows Settings:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Title bar: DC-Assessor · contoso.com · assessed 2026-10-05 14:32  [Export]│
├───────────────┬────────────────────────────────────┬─────────────────────┤
│ Navigation    │ Main list / table                  │ Detail pane         │
│ tree          │ (sortable, filterable, virtualized)│ (selected finding   │
│               │                                    │  or object)         │
│ Overview      │                                    │                     │
│ ▸ On-prem AD  │                                    │                     │
│   ▸ Privileged│                                    │                     │
│   ▸ ACLs      │                                    │                     │
│ ▸ Entra ID    │                                    │                     │
│ ▸ Microsoft365│                                    │                     │
│ ▸ Azure       │                                    │                     │
│ ▸ Endpoints   │                                    │                     │
│ Baselines     │                                    │                     │
│ Threat hunting│                                    │                     │
│ Attack paths  │                                    │                     │
│ Compare       │                                    │                     │
├───────────────┴────────────────────────────────────┴─────────────────────┤
│ Status bar: catalog v1.4 · 804 checks · 61 not assessed (why) · bundle path│
└──────────────────────────────────────────────────────────────────────────┘
```

Rules that keep it from becoming a card dashboard:

- Information is shown as **tables, lists and text**. Charts are used only where a chart says something a table can't, such as trend over runs, the severity distribution, or the attack graph.
- The overview has **one score strip**, not tiles: overall score, then the On-prem / Entra / M365 / Azure / Endpoints scores in a single row, followed by a ranked table of the top risks.
- No decorative counters, no badges that repeat what a column already says, and no status indicators that don't map to a real state.
- **Empty states are honest.** If an area wasn't collected, it says "Not assessed: requires Event Log Readers on DCs" with a link to the fix. It never shows placeholder numbers or sample rows.

### Screen list

| Screen | Content |
|---|---|
| **Start** | Recent assessments (from the assessments folder: name, scope, date, score), plus *New assessment* and *Open bundle*. On first launch the list is empty and says so; nothing is pre-filled. |
| **New assessment** | The 5 steps from section 3. |
| **Overview** | Score strip, top risks table, change since the previous run (if one exists), coverage summary (assessed / not assessed areas). |
| **Area view** (one per area, from the tree) | Table of every check in the area: status, severity, check title, affected-object count, framework refs. Selecting a row fills the detail pane. |
| **Finding detail** (pane) | What is wrong, why it matters, evidence (actual attribute values), affected objects (with their real icons), remediation steps with copyable PowerShell/portal paths, references, "accept risk" (exception with reason and expiry). |
| **Object view** | Any user/group/computer/GPO/app/role: its attributes, memberships, ACL entries that matter, and every finding that involves it. |
| **Attack paths** | Graph view of shortest paths to Tier 0 / Global Admin, using the real object icons as nodes. Choke-point table beside it. |
| **Baselines** | Pick a baseline, then a table of every setting: expected, actual, source (GPO / Intune profile / local), and machines failing. |
| **Threat hunting** | Timeline and table of observations with confidence. Kept visually separate from configuration findings. |
| **Compare** | Choose two assessments: new, fixed and unchanged findings, plus score change per area. |
| **Exports** | Choose report types, branding (logo, organization name, classification label), and redaction. |
| **Settings** | Assessments folder, thresholds (stale days, password age), exception list, catalog version and update from file, theme (light/dark/system). |

---

## 5. Visual design

### 5.1 Palette: Claude-inspired, deliberately small

A warm neutral base with one accent, plus a short severity scale. Values are taken from the Claude app's look (warm ivory/charcoal backgrounds and the clay-orange accent). They will be checked against WCAG AA contrast in both themes before use.

**Neutrals and accent**

| Token | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#FAF9F5` ivory | `#262624` charcoal | App background |
| `surface` | `#FFFFFF` | `#30302E` | Panes, tables |
| `surface-alt` | `#F0EEE6` | `#1F1E1D` | Nav tree, header rows, zebra rows |
| `border` | `#E5E2D9` | `#3E3E3A` | Dividers |
| `text` | `#141413` | `#F5F4EF` | Body text |
| `text-muted` | `#6B6A65` | `#A6A39A` | Secondary text |
| `accent` | `#C96442` clay | `#D97757` | Primary buttons, selection, links, focus ring |
| `accent-soft` | `#F5E6DF` | `#4A3329` | Selected row, hover |

**Severity scale** (the only other colors in the app)

| Severity | Light | Dark |
|---|---|---|
| Critical | `#B42318` | `#F97066` |
| High | `#D9661F` | `#F79A5B` |
| Medium | `#B88A1B` | `#E4BE5C` |
| Low | `#5E7A3C` | `#9DBB7A` |
| Info / Not assessed | `#5B6B7A` | `#9AA8B5` |

Rules:
- Severity colors appear only as a small square or text marker next to the severity word, never as full-row fills or big colored tiles. Severity is always written as a word too, so it never depends on color alone.
- Charts use the severity scale for severity and the accent plus neutrals for everything else. There are no rainbow palettes.
- The Claude logo and the Anthropic name are not used. The app takes inspiration from the palette and typography only and has its own name and icon.

### 5.2 Fonts

The Claude app's own typefaces are proprietary and can't be shipped. The plan uses free, open-license fonts that read the same way, bundled inside the app so nothing loads from the internet:

| Role | Font | License |
|---|---|---|
| UI text, tables, labels | **Inter** (or "Geist" as an alternative) | SIL Open Font License |
| Headings and report titles | **Source Serif 4** (a serif, echoing Claude's serif headings) | SIL OFL |
| Code, commands, DNs, SIDs | **JetBrains Mono** | SIL OFL |

Type scale: 13px base for dense tables (admins expect density), 14px for body text in panes, and 20/24/32px for headings. Tabular numbers are used in all numeric columns.

### 5.3 Icons: real ones, not drawn

| Need | Source | How it gets into the app |
|---|---|---|
| **AD objects** (user, group, computer, OU, GPO, DC, container, contact, trust, site) using the exact icons from ADUC/GPMC | Windows' own system files (`dsadmin.dll`, `gpoadmin.dll`, `imageres.dll`, `shell32.dll`) | **Read at runtime from the Windows machine the app runs on**, using the Win32 icon extraction API. The app doesn't redistribute Microsoft's files, so the icons are 100% original and always match that Windows version. A fallback (below) is used only if a DLL is missing, for example on Server Core without RSAT. |
| **Microsoft cloud services** (Entra ID, Exchange, SharePoint, Teams, Intune, Defender, Key Vault, Azure subscription, enterprise app, managed identity, PIM, Conditional Access) | **Microsoft Azure Architecture Icons** and **Microsoft 365 / Entra product icons** (official SVG sets published by Microsoft) | Bundled as SVG. **Action needed:** Microsoft's terms allow these icons in architecture diagrams and documentation. Before shipping, confirm the terms cover use inside a product UI (and for a commercial product, check the Microsoft trademark guidelines). If they don't, the fallback is Fluent icons for UI chrome, and the official icons appear only in exported reports. |
| **UI chrome** (navigation, buttons, filters, export, settings, warnings) | **Fluent UI System Icons**, Microsoft's own open-source icon set (MIT license) | Bundled as SVG. This is the same family Windows 11 and Microsoft 365 use, so the app feels native. |
| **Fallback for AD objects** | Fluent UI System Icons equivalents (Person, People, Desktop, Folder, Shield, Server) | Bundled. |

No emoji, no hand-drawn SVGs and no generic stock icon packs.

### 5.4 Charts, sparingly

ECharts with a custom theme built from the tokens above. The only charts in the app:
- Severity distribution (one horizontal stacked bar, not a donut)
- Score trend across assessments (a line, shown only when two or more real assessments exist)
- Password/last-logon age histograms in hygiene areas
- Baseline compliance per baseline (horizontal bars)
- The attack-path graph (Cytoscape.js)

Every chart has a "view as table" toggle.

---

## 6. No dummy data: how it is enforced

- The app ships with **no sample assessment** and no demo mode. On first launch everything is empty, and each empty state says what to do next.
- Developers use fixture bundles from the test lab (main plan, section 9). These live in `tests/fixtures/` and are **excluded from the release build**. A CI check fails the build if any fixture file or any string from it appears in the release output.
- **No placeholder statuses.** A UI review checklist bans words like "Live", "Active", "Online", "Running" or "Healthy" unless they are the literal value of a real attribute or the state of a job actually running. Progress shows real counts.
- Timestamps shown are real collection and analysis times, from the bundle's manifest.

---

## 7. Backend

There is **no server**. The backend is a Rust core that runs inside the app process on the user's machine. The UI calls it through Tauri's local IPC (in-process, not HTTP), so there is nothing to host, no port to open, and no network latency.

```
┌─────────────────────────── DCAssessor.exe ───────────────────────────┐
│                                                                      │
│  UI (Svelte in WebView2)                                             │
│     │  commands (invoke)          ▲ events (progress, results ready) │
│     ▼                             │                                  │
│  ┌────────────────────── Rust core ──────────────────────────────┐   │
│  │ Job runner      starts/cancels collection & analysis jobs,    │   │
│  │                 each on its own worker thread                 │   │
│  │ Collector host  runs bundled PowerShell collectors as child   │   │
│  │                 processes, reads their JSON-lines progress    │   │
│  │ Cloud client    Microsoft Graph / Exchange / ARM calls with   │   │
│  │                 sign-in (MSAL), paging, batching, throttling  │   │
│  │ Bundle store    writes/reads the .zip bundle, hashes, crypto  │   │
│  │ Engine          normalizes data, runs checks, builds attack   │   │
│  │                 graph, scores, diffs runs                     │   │
│  │ Query layer     serves the UI: paged, sorted, filtered rows,  │   │
│  │                 full-text search, object lookups              │   │
│  │ Exporters       PDF (WebView2 print), XLSX, CSV, JSON, SARIF  │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                │                                     │
└────────────────────────────────┼─────────────────────────────────────┘
                                 ▼
              powershell.exe collectors ──▶ LDAP / SMB / WinRM / event logs
```

| Component | Built with | Notes |
|---|---|---|
| Job runner | Rust, `tokio` | Collection and analysis never run on the UI thread. Each job can be cancelled. |
| On-prem collectors | PowerShell 5.1 scripts, bundled | They emit one JSON line per progress step (`{"area":"users","read":12408,"total":48000}`), which become real progress events in the UI. |
| Cloud collectors | Rust `reqwest` + MSAL sign-in | Uses Rust rather than PowerShell for better control of paging, retries and Graph throttling. |
| Local data store | **SQLite** (embedded file, one per assessment) next to the bundle | The engine loads results into SQLite with indexes and full-text search (FTS5), so the UI can sort, filter and search 500k objects instantly. It is a single file with no database server, and can be rebuilt from the bundle at any time. |
| Engine | Rust | Checks are data files; rule logic is compiled into the engine with parameters from the catalog. The attack graph uses `petgraph`. |
| Exports | WebView2 PrintToPdf, `rust_xlsxwriter` | Reports reuse the UI components, so they look identical to the app. |

---

## 8. UI/UX quality bar (non-negotiable)

The UI is the product. These are acceptance criteria: a release that misses one doesn't ship.

**Speed**
- App opens to the Start screen in **under 1.5 s**.
- Opening an existing assessment shows the overview in **under 1 s** (results come from the indexed SQLite file, not by re-reading the bundle).
- Every click, sort, filter and search responds in **under 100 ms** at 500k objects. Tables are virtualized, so only visible rows render.
- Scrolling stays at 60 fps. Nothing long-running blocks the UI. Collection and analysis run in the background and the user can browse other assessments meanwhile.

**Clarity**
- Every finding answers four questions without extra clicks: what is wrong, why it matters, which objects, and how to fix it.
- Plain language first and technical detail second (DNs, SIDs and attribute values sit in the detail pane, in monospace, and are copyable).
- Severity is always a word plus a color marker, never color alone.
- Every number on screen can be clicked through to the objects behind it.

**Craft**
- An 8px spacing grid, consistent alignment, and no layout shift when data loads.
- Light and dark themes are designed together. Both pass WCAG AA contrast.
- Full keyboard use: arrow keys in tree and tables, `Ctrl+F` search, `Ctrl+K` command palette (jump to any check, area or object), Enter opens details, Esc closes.
- Screen-reader labels on all controls. Supports Windows text scaling and high-contrast mode.
- Windows-native behavior: remembers window size and position, follows the system theme, uses native file dialogs, and supports high-DPI and multiple monitors.
- Motion is limited to short, functional transitions (under 150 ms) for pane open/close. There is no decorative animation, and the app respects "reduce motion".

**Honesty** (from section 6)
- Real data only, real progress only, honest empty states.

**How it is verified**
- **Design before code.** A high-fidelity clickable prototype of every screen is built and approved by you before any backend work starts. It uses data from the test lab, clearly marked as a prototype, and is never shipped.
- **Performance tests in CI** against a 500k-object lab bundle. A build fails if any interaction budget above is exceeded.
- **Visual regression tests** (Playwright screenshots, light and dark) catch unintended UI changes.
- **Accessibility tests** (axe-core) run in CI.
- **Usability check** with 2 or 3 AD admins on the prototype before the build is finalized.

---

## 9. Build and release

- Monorepo layout extends the main plan:
  ```
  app/            Tauri shell (Rust) and engine crate
  ui/             Svelte UI (also builds the offline HTML export)
  collectors/     PowerShell collectors (shared with CLI)
  checks/         catalog
  assets/icons/   Fluent + Microsoft service icons (with license files)
  ```
- GitHub Actions: build MSI and portable ZIP on Windows runners, then sign them (code-signing certificate needed, see decisions), run Pester and Rust tests, UI tests (Playwright against the built UI with fixture bundles), run the dummy-data guard, and check bundle size (fail above 25 MB).
- Release artifacts: `DCAssessor-x.y.z.msi`, `DCAssessor-x.y.z-portable.zip`, `checks-catalog-x.y.zip` (catalog updates without reinstalling), and SHA-256 hashes.

---

## 10. Decisions for you

1. **App stack:** Tauri desktop app with PowerShell collectors and a Rust engine *(recommended, smallest and fastest)*, or a WPF/.NET 8 app *(native Windows controls, but a larger download and a less flexible design)*.
2. **Microsoft service icons:** use the official Azure/M365 icons in the UI after checking their terms *(recommended)*, or keep them to exported reports only and use Fluent icons in the UI.
3. **Code signing:** buy an OV/EV code-signing certificate *(recommended, otherwise SmartScreen warns on install)*, or ship unsigned for internal use only.
4. **Fonts:** Inter + Source Serif 4 *(recommended)*, or license the actual proprietary fonts if you have access.
