# Spider Stone

**English** · [Русский](README.ru.md)

A tool for analyzing **Windows Optional Features** and their components: given a feature
name, it reconstructs the full "feature → packages → components → files" chain from
Component-Based Servicing (CBS) data, decompresses WinSxS manifests via `wcp.dll`, and
exports a detailed component map (files with hashes, dependencies, registry, categories,
etc.) to CSV and a readable HTML report.

Runs **fully locally** — nothing is uploaded to the network.

---

## Contents

| File | Purpose |
|---|---|
| `Spider-Stone.ps1` | Main script: CBS registry search, manifest collection, parsing, export |
| `WCPExtractor.psm1` | Module that decompresses WCP-compressed files (manifest decompression via `wcp.dll`) |

Both files must live in the same folder.

---

## Requirements

- **PowerShell 7.0+**
- Windows 10/11 or Windows Server (x64, x86, or ARM64)
- Administrator rights (recommended — to read CBS registry keys and WinSxS files)
- `wcp.dll` present on the system (found automatically; can be specified manually)

---

## How it works

```
FeatureName
   │  registry: Component Based Servicing\{OptionalFeatures, UpdateDetect}
   ▼
Single fast scan of Packages (.NET RegistryKey API):
Packages (Packages\*\Updates)  ──► Owner packages (Packages\*\Owners) ──► [MUM files]
   │  package name → manifest prefix (arch_ + name, suffixes trimmed)
   ▼
Manifests  C:\Windows\WinSxS\Manifests\<prefix>*.manifest   (WCP-compressed)
   │  WCPExtractor: wcp.dll → decompress to XML
   ▼
Parse <assembly>: files + the component's full footprint
   ▼
Output: CSV (per data kind) + HTML report + GridView
```

> **Performance.** Package discovery uses the native .NET `Microsoft.Win32.RegistryKey`
> API (instead of the `Get-ChildItem`/`Get-ItemProperty` provider) in a single pass over
> the hive. On a system with ~15,000 CBS packages, a full analysis of the `DiskIo-QoS`
> feature dropped from **~570 s to ~5 s** (~110×). Memory stays minimal (only the set of
> matched package names is kept), so no separate memory-saving switch was needed.

---

## `Spider-Stone.ps1` parameters

| Parameter | Type | Description |
|---|---|---|
| `-FeatureName` | string | Name of the Optional Feature to analyze. Without it — lists the installed features. |
| `-OutputDirectory` | string | Output directory for results. Default: `.\OptionalFeatureFiles`. |
| `-ParsingMum` | switch | Enable recursive parsing of MUM files from `C:\Windows\servicing\Packages`. |
| `-NotShowGridView` | switch | Do not open results in `Out-GridView`. |
| `-OpenReport` | switch | Open the generated HTML report in the default browser when done. |
| `-ComponentFilter` | string | Output only components whose name contains this word (case-insensitive). Filters every data kind: files, dependencies, registry, CSV, HTML, GridView. |
| `-PathToWcp` | string | Explicit path to `wcp.dll` for decompression. |
| `-SearchWcpDll` | switch | Find and show the latest `wcp.dll` for the system architecture (via `Find-LatestWCPDll`). |
| `-VerboseOutput` | switch | Verbose logging. |
| `-Help`, `-?` | switch | Show the built-in (bilingual) help. |

---

## Examples

```powershell
# List installed Optional Features
.\Spider-Stone.ps1

# Analyze a specific feature
.\Spider-Stone.ps1 -FeatureName "Windows-Defender-Default-Definitions"

# With recursive MUM parsing and verbose log
.\Spider-Stone.ps1 -FeatureName "RSAT" -ParsingMum -VerboseOutput

# Only components whose name contains "Defender"
.\Spider-Stone.ps1 -FeatureName "Containers" -ComponentFilter "Defender"

# Custom output directory, no GridView
.\Spider-Stone.ps1 -FeatureName "RSAT" -OutputDirectory "C:\Temp\RSAT" -NotShowGridView

# Use a specific wcp.dll
.\Spider-Stone.ps1 -FeatureName "RSAT" -PathToWcp "C:\Windows\System32\wcp.dll"

# Just find the latest wcp.dll
.\Spider-Stone.ps1 -SearchWcpDll
```

---

## Output

Everything is written to `<OutputDirectory>\<Feature>\`. There is one CSV per data kind,
plus a summary HTML report.

| File | Contents |
|---|---|
| `OptionalFeatureFiles_<Feature>.csv` | Component files (enriched — see below) |
| `Components_<Feature>.csv` | One row per component: full identity + DisplayName/Description + file count |
| `Dependencies_<Feature>.csv` | Component → component dependency edges (`dependentAssembly`) |
| `Registry_<Feature>.csv` | Registry footprint: keys/values the component installs |
| `Categories_<Feature>.csv` | Category/feature membership (`categoryMembership`) |
| `Directories_<Feature>.csv` | Directories the component creates, + their SDDL |
| `Strings_<Feature>.csv` | Localization (`stringTable`): displayName/description, etc. |
| `Providers_<Feature>.csv` | The component's ETW providers |
| `Tasks_<Feature>.csv` | Scheduled tasks the component registers |
| `Extras_<Feature>.csv` | Markers: deployment / infFile / appxRegistration / serviceData / migration / protocolDriver |
| `Report_<Feature>.html` | Self-contained HTML report (summary cards + collapsible tables, dark/light theme) |

### What is extracted per component file

`FileName`, `DestinationPath`, `SourceName`, `ImportPath`, `SourcePath`, `WriteableType`,
`HashAlgorithm` + `HashValue` (the file's SHA hash), `SecurityDescriptor` (SDDL name),
`LinkTarget` (hardlinks), plus the component identity (`Component`, `Version`,
`Architecture`, `PublicKeyToken`).

### HTML report

Generated **automatically** for any feature analysis — no separate switch is needed, just
pass `-FeatureName`. When the run finishes, the file path is printed to the console
(line `HTML report : ...`). The path is printed as a terminal hyperlink (OSC 8) and is
highlighted — **but Windows Terminal, for security, only opens `http`/`https` on click,
not local `file://` links**. To open the report automatically, run with **`-OpenReport`**
(launches the default browser):

```powershell
.\Spider-Stone.ps1 -FeatureName "DiskIo-QoS" -OpenReport
```

Or open the path manually (`Invoke-Item <path>`) — it is always printed to the console.

The local file `Report_<Feature>.html` opens in any browser with no internet. Summary
cards on top, then collapsible sections per data kind (sticky table headers, monospace
font for hashes/keys/GUIDs). Large tables (registry) are capped at 500 rows with a note —
the full data is in the corresponding CSV.

```powershell
.\Spider-Stone.ps1 -FeatureName "DiskIo-QoS"
# -> .\OptionalFeatureFiles\DiskIo-QoS\Report_DiskIo-QoS.html
Invoke-Item .\OptionalFeatureFiles\DiskIo-QoS\Report_DiskIo-QoS.html   # open it
```

### Progress

All long-running stages — CBS package search, owner-package search, copying,
WCP decompression, and manifest parsing — show a progress bar (`Write-Progress`) with the
current item number and percentage, so it is clear the script is working and not hung.

---

## `WCPExtractor.psm1` module

Exported functions:

| Function | Purpose |
|---|---|
| `Expand-WCPFile -InputFile <path> [-OutputFile <path>] [-WCPDllPath <path>]` | Decompress a WCP-compressed file (manifest) to XML. Uncompressed files pass through. |
| `Find-LatestWCPDll` | Find the latest `wcp.dll` for the system architecture (System32 + WinSxS servicing stack). |
| `Test-WCPManifest [-ManifestName <name>] [-OutputPath <dir>]` | Trial decompression of a WinSxS manifest + XML validation. |
| `Test-WCPManifestCompressed -InputFile <path>` | Whether a manifest is compressed (native `IsManifestCompressed`). Returns `$null` if the export is absent in this build. |
| `Get-WCPCompressionTypeName -Code <n> [-Bytes <byte[]>]` | Human-readable compression-type name for a numeric `GetCompressedFileType` code. |
| `Get-ProcessorArchitecture` | `x86` / `x64` / `arm64`. |

### How decompression works

`Expand-WCPFile` loads `wcp.dll` at runtime (the live library is the source of truth — its
version may change) and calls the native functions:
`GetCompressedFileType` → `InitializeDeltaCompressor` →
`LoadFirstResourceLanguageAgnostic` → `DeltaDecompressBuffer`.

**WCP compression types** (header `'D' 'C' <T> 0x01`):

| Signature | Code | Handling |
|---|---|---|
| `DCM\x01` | 4 | Delta manifest — **decompressed** (the main path) |
| `DCS\x01` | 5 | LZMS store — detected, extension point (not decompressed) |
| `DCD/DCN/DCH/DCX` | 1/2/3/6 | Detected, clear diagnostics (not decompressed) |
| no header | 0 | Not WCP-compressed — file returned as-is |

---

## Technical details

**CBS registry keys:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Notifications\OptionalFeatures`
- `HKLM\...\Component Based Servicing\UpdateDetect`
- `HKLM\...\Component Based Servicing\Packages` (`Updates`, `Owners` subkeys)

**Paths:** manifests — `C:\Windows\WinSxS\Manifests`; MUM — `C:\Windows\servicing\Packages`.

**Manifest parsing** is namespace-agnostic (asm.v1/v2/v3, xmldsig, ETW, task-scheduler) —
via `local-name()` XPath.

**Architecture support:** x64 (AMD64), x86 (i386), ARM64 — detected automatically, with the
matching `wcp.dll` selected.

---

## Sources, credits, and license

**Online source the development is based on:**

- **wcpex** by Smx (Stefano Moioli) — <https://github.com/smx-smx/wcpex/> — the reference
  implementation for decompressing WCP-compressed manifests via native `wcp.dll` calls
  (`GetCompressedFileType` → `DeltaDecompressBuffer`). The `WCPExtractor.psm1` module is a
  PowerShell port of this technique; the original (zlib-style) license is preserved in the
  module header.

**Other:**

- The WCP compression header format (`'D' 'C' <T> 0x01`) and the type enum were checked
  against decompiled system servicing libraries (`ServicingCommon.dll`); these constants
  have no public online description, so `wcp.dll` is loaded at runtime as the source of
  truth (its version/enum may change).
- The CBS / WinSxS / manifest model is the standard Windows servicing mechanism.

> Honestly: the only external online project a technique was borrowed from is **wcpex**.
> Everything else is analysis of system structures and standard APIs, with no code copied
> from the network.
