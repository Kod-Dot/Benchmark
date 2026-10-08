# Benchmark

A read-only configuration and security assessment tool for on-premises Active Directory, Microsoft Entra ID, Microsoft 365, Azure and Windows endpoints. It runs as a small Windows desktop app and needs no server.

> **Status: early development.** This build collects and analyzes on-premises Active Directory (LDAP, certificate services, SYSVOL, domain controller configuration and event logs), Windows member servers and workstations, Microsoft Entra ID and Intune (Microsoft Graph, after a delegated Microsoft sign-in), Exchange Online, SharePoint Online, Teams, Purview and Azure resources. It shows the results dashboard, threat hunting, compliance mapping, account ages and the score over time; compares runs, records accepted risks, opens bundles collected on other computers, and exports executive, technical and change reports. 802 of the 804 catalog checks run; the rest are listed in [`docs/plans/pending-checks.md`](docs/plans/pending-checks.md).

## What is here

| Path | What it is |
|---|---|
| `checks/` | The check catalog as data: groups, areas, data sources, and one file per area listing its checks. 804 checks are defined; 802 are `implemented`, the rest `planned`. |
| `crates/dca-core/` | Rust core: the catalog, the analysis rules for every area, results and scores, accepted risks, bundles and report export. No UI dependency, so it is unit-tested on any platform. |
| `app/` | The desktop app: Svelte 5 interface (`app/src`) and the Tauri 2 shell (`app/src-tauri`). |
| `collectors/` | PowerShell collectors, run by the app with the Windows PowerShell 5.1 that ships with Windows: `Test-DCAAccess.ps1` (what the current account can read), `Invoke-DCACollect.ps1` (Active Directory, domain controllers, endpoints) and `Invoke-DCAEntra.ps1` (Entra ID, Exchange Online, Azure). |
| `tools/` | Development checks, including the read-only guard that fails CI if a collector could change anything. |
| `docs/plans/` | The assessment plan (check catalog by area) and the application plan (install, screens, visual design, backend). |

## Building

Requirements: Rust (stable), Node.js 22, and on Windows the [Tauri prerequisites](https://tauri.app/start/prerequisites/) (WebView2 is already present on Windows 10/11).

```powershell
cd app
npm ci
npx tauri dev      # run the desktop app
npx tauri build    # build the MSI into target/release/bundle/msi
```

Tests and checks:

```powershell
cargo test -p dca-core                         # core unit tests, including catalog validation
cargo run -p dca-core --bin catalog-summary    # prints catalog counts as JSON
cd app; npm run check                          # Svelte and TypeScript checks
pwsh ./tools/Test-CollectorsReadOnly.ps1       # read-only guard for collectors
node tools/check-no-fixture-data.mjs           # no example data in the built app (after npm run build)
cd app; node tests/a11y.mjs                    # axe-core WCAG 2.1 AA check of every screen (needs the preview data below)
node tools/check-graph-schema.mjs              # cloud requests and fields against Microsoft's Graph schema (v1.0 and beta)
pwsh ./tools/Test-CollectorHelpers.ps1         # unit tests for the collector's helper functions
```

### Testing without a lab

No domain or tenant is needed to test the collectors against real systems:

- **Real Windows output.** `tools/Read-LocalMachine.ps1` runs the collector's own domain controller, endpoint and
  event log reads against the machine it is on and writes the replies the collector would. CI runs it on a GitHub
  Windows Server runner, then `cargo test -p dca-core -- --ignored live_windows_replies` (with `DCA_LIVE_DIR` set
  to that folder) fails if the analysis does not understand any part that came back, and the script fails if
  Windows rejects any event log query. Parts a machine that is not a domain controller cannot read are reported,
  not failed.
- **Microsoft Graph.** `tools/check-graph-schema.mjs` checks every Graph path, `$select`, `$expand` and `$filter`
  the Entra collector sends, and every property name the analysis reads, against Microsoft's published Graph
  metadata.

For a full run, a Windows Server evaluation domain in Hyper-V and a Microsoft 365 developer or trial tenant work.

### Keyboard

`Ctrl+K` opens a palette that jumps to any page, area, check or object. `Ctrl+F` goes to the search box of the screen you are on. In the findings and directory tables the arrow keys, Home and End move between rows and Enter opens one. Long tables (the directory, a finding's affected objects, account ages) render only the rows on screen, so a directory of 500,000 objects scrolls and filters without waiting. `Esc` leaves a finding or object page. Windows high-contrast themes are supported: charts keep their colours with outlines, and selected items are outlined.

### Browser preview of the interface

The interface can be reviewed in a browser without the desktop app. There is no backend there, so it shows the real catalog plus the example assessments in `fixtures/example-assessments/` (generated by `fixtures/make_examples.py`). Every screen that shows them carries an "Example data" tag; the desktop app never loads them.

```powershell
cargo run -q -p dca-core --bin preview-data   # writes app/.preview/*.json
cd app; npm run dev
```

## Running a collector on its own

The collectors can run without the app, for example on a domain controller or a server with no desktop. `-Bundle` keeps the progress log and packs the output into a .zip; copy it to the computer with the app and choose **Open bundle** on the start screen, which analyzes it into a new assessment.

```powershell
.\Invoke-DCACollect.ps1 -Domain corp.example.com -OutDir C:\Temp\dca -Sources ldap,sysvol,dc-remote,dc-events -Bundle C:\Temp\dca-corp.zip
```

A .zip of a whole assessment folder, copied from another computer, opens the same way.

The app also works from the command line, to analyze bundles and write reports in scripts or scheduled tasks. Pipe to `Out-Host` so PowerShell waits for it; `Benchmark.exe help` lists every option.

```powershell
Benchmark.exe analyze C:\Temp\dca-corp.zip | Out-Host
Benchmark.exe export "$env:LOCALAPPDATA\Benchmark\Assessments\20261006-0930-corp.example.com" --out D:\Reports --reports executive,remediation --formats pdf,xlsx | Out-Host
Benchmark.exe list | Out-Host
```

## Principles

- **Read-only.** Collectors only query. CI enforces this with `tools/Test-CollectorsReadOnly.ps1`.
- **No dummy data.** Every value on screen comes from the catalog, the machine, or a real assessment. Empty states say what is missing and why.
- **No server.** Everything runs in one desktop process. Assessments are plain folders on disk.

## Third-party assets

- [Fluent UI System Icons](https://github.com/microsoft/fluentui-system-icons) by Microsoft, MIT license.
- Fonts: [Inter](https://rsms.me/inter/), [Source Serif 4](https://github.com/adobe-fonts/source-serif) and [JetBrains Mono](https://www.jetbrains.com/lp/mono/), all SIL Open Font License, bundled through Fontsource.
