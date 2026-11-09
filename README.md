# WARDOGS Scanner

[![Build scanner](https://github.com/bloodybaker/wardogs-scanner/actions/workflows/build.yml/badge.svg)](https://github.com/bloodybaker/wardogs-scanner/actions/workflows/build.yml)

Consent-based Windows diagnostics for human review of WARDOGS moderation appeals.
Windows 10/11 x64, .NET 10 WPF, portable self-contained executable.

Source: https://github.com/bloodybaker/wardogs-scanner
Community service: https://wardogs.com.ua/scanner
Downloads: https://wardogs.com.ua/scanner
Direct EXE: https://github.com/bloodybaker/wardogs-scanner/releases/download/v0.7.5/WardogsScanner.exe

## Current version: 0.7.5

This release adds embedded privacy information, public source, licensing notices
and GitHub/SignPath build preparation. Detection behavior is unchanged from 0.7.4.
This release is unsigned; SignPath Foundation approval is pending. The permanent
download page publishes the server-approved version and SHA-256. Its download
button points to a versioned GitHub EXE, so future releases can update the download
and server approval together. Do not bypass Windows protection.

The scanner requires administrator elevation, a one-time code and explicit consent.
It reads process/file/module metadata, execution and persistence traces, protection
state, device information, game-access handles and bounded script/command context.
Browser matching is local; only matched URLs, relevant search queries, visit counts
and timestamps are reported. Reports include technical paths and a pseudonymous
device hash and go over HTTPS to wardogs.com.ua after consent. Raw command lines,
scripts and memory contents, unrelated history, cookies, credentials, private
documents, photos and messages are not uploaded. Findings require human review.

Read [Privacy](PRIVACY.md) before scanning. Declining consent prevents the scan;
there is no offline end-user scan mode. Close and delete the portable application
to remove it; this does not delete reports already transferred to the server.

## Code signing policy

[Code signing policy](CODE_SIGNING.md) lists the responsible maintainer and release
controls. SignPath Foundation acceptance and signing are pending. Downloads must
not be represented as Foundation-signed until a certificate is approved and used.

## Licensing

Original code and owner-authored logo: [MIT](LICENSE). e-Ukraine fonts: CC BY 4.0,
unmodified, with [attribution](licenses/e-Ukraine-NOTICE.md). Dependencies retain
their own licenses. [Third-party notices](THIRD_PARTY_NOTICES.md) and all license
texts are included in the release ZIP and linked above for direct EXE users.
See [SignPath setup](SIGNPATH-SETUP.md).

## Build and test

Install the exact SDK in global.json. From the repository root:

```powershell
dotnet run --project tests/Wardogs.Scanner.Smoke -c Release -- --fixtures
.\build.ps1 -OutputDirectory "$PWD/artifacts/local" -LockedRestore
.\scripts/package-release.ps1 -ArtifactDirectory "$PWD/artifacts/local"
```

Fixtures use synthetic data. Live collection is opt-in and should only be run
with the machine owner's consent. GitHub Actions builds unsigned candidates;
the separate signing workflow requires configured SignPath credentials and
manual approval. Hashes for release publication must come from final signed bytes.

## Historical release notes

The notes below document earlier versions and experiments. Current privacy
boundaries above and PRIVACY.md take precedence.

## 0.5 changes and evidence boundaries

- Browser catalog: 31 scoped rules and 18 contextual keywords, catalog version `2026-10-13.1`. Matching is local; only predefined terms, rule IDs, visit aggregates and timestamps are exported. A visit/search is not proof of running a cheat.
- Browser cleanup: Firefox clear-on-exit policy, optional Chromium legacy clearing marker, and bounded NTFS V2 file-delete/truncation events matched by profile directory file ID. Normal `History-wal` truncations are excluded. Empty/missing/new history is not proof of deliberate cleanup; SQLite row deletion often leaves no reliable clearing timestamp.
- Hardware: read-only CIM runtime VBS/HVCI and PCIe candidate checks. DMA capability is not active Kernel DMA Protection. The public PCILeech default ID is a review candidate, not proof of a cheat. Custom firmware, disconnected hardware and in-game DMA activity are outside coverage.
- False positives: exclude the actual scanner PID from process/game-module collection; AppData service/task paths alone are informational. Backend 0.5 reports suppress only the identical build hash, never arbitrary binaries renamed to WardogsScanner. Legacy reports retain their existing display filter.
- No kernel driver installed, PCI registers modified, raw memory dumped, security settings weakened, or unrelated browser content uploaded.

### Scanner research used (reviewed 2026-10-13)

Vendor descriptions document claimed capabilities, not independent sensitivity/specificity measurements. No vendor binaries were executed and no proprietary signatures copied.

| Primary source | Useful direction | Interpretation for this project |
| --- | --- | --- |
| [Echo](https://echo.ac/) | Execution/deletion timeline, Prefetch, Amcache, memory and device artifacts | Correlate artifact identity and time. A list of software is not a cheating verdict. |
| [Ocean detection systems](https://anticheat.ac/docs/detections/detection-systems) | Executed then modified/deleted, removed Prefetch, external media | Updaters and normal maintenance have similar traces; require context. |
| [Ocean suspicious logs](https://anticheat.ac/docs/detections/suspicious-logs) | Explains heuristic warnings | Do not copy C#/.NET, packer or macro-tool presence as standalone cheat rules. |
| [Detect documentation](https://detect.ac/docs) | Browser clear events, PCIe/DMA candidates, device anomalies | Public descriptions are not validation; especially avoid treating bad EDID or a vendor ID as conclusive cheating. |
| [drvscan](https://github.com/ekknod/drvscan) | PCI configuration/feature checks, process integrity | Requires driver; archived with Win11 24H2 caveat. Not bundled or run. |
| [EmuScan](https://github.com/Manut0/emuscan) | PCI device emulation inconsistencies | Limited common-device coverage; driver/test-signing workflows unsuitable for this portable release. Not bundled. |
| [PECmd](https://github.com/EricZimmerman/PECmd) | Structured Prefetch parsing | Future parser should distinguish embedded run times from filesystem modification time. Current module is metadata only. |
| [Velociraptor BAM](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam/) | Timestamped execution artifact interpretation | BAM coverage is limited; missing records do not establish innocence. |
| [Microsoft USN V2](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2) | Parent file reference, reason and record timestamp | File event does not identify actor, intent, or individual deleted browser rows. |
| [Microsoft DeviceGuard](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) | Runtime versus configured security properties | Report unknown as unknown, not disabled. |
| [PCILeech FPGA](https://github.com/ufrisk/pcileech-fpga/blob/master/ac701_ft601/readme.md) | Public AC701 default identity | Legitimate research device and mutable ID; manual review only. |

New domain provenance: public product/catalog pages at buywardogscheat.org/wardogs-cheats/, cheatforwardogs.org/, cheatforwardogs.net/wardogs-cheats/, wardogscheatspc.com/blog/wardogs-cheat-license-guide, nowaxcheats.com/store/wardogs/full and phantomdma.cc/products. These pages advertise products; their existence does not validate product claims or the visitor's intent.

Next research work, not implemented in 0.5: signed/versioned content-signature corpus with benign fixtures; structured Prefetch/Amcache parsing; full-path execution/deletion correlation; independently tested device-emulation inspection with a maintained signed driver. The current build must not advertise these as shipped detections.

Offline regression checks (synthetic profiles only):

```powershell
dotnet run --project tests/Wardogs.Scanner.Smoke -c Release -- --fixtures
```

Live scanning is explicitly opt-in with `--live`; it reads this machine's artifacts and should only be used with the owner's consent.


Native check in the development session: runtime_security succeeded; CIM PCI enumeration timed out, and the registry fallback returned 22 entries while preserving a partial status. NTFS journal access was unavailable in this session, so only the synthetic USN parser checks were verified; a real elevated NTFS deletion round trip remains unverified here.

`drvscan` source review (`Client/scan/pci.cpp`) confirms separate configuration, driver presence, hidden-device, interrupt-activity and feature tests. These are deeper than vendor-ID matching. Some paths actively write PCI configuration and depend on kernel internals; transplanting this implementation would require a separate signed-driver project and representative hardware regression testing. The current release implements none of these active tests.

## Scanner 0.6: repeated-device checks and PDF export

The scanner hashes the SMBIOS system UUID with a WARDOGS-specific namespace before upload. No raw UUID, serial number or MAC address is sent. Invalid/empty SMBIOS IDs use a separately labelled Windows-installation hash; when both sources are unavailable, repeat status is unknown. The consent screen explicitly includes the device identifier. The identifier is a correlation aid and is not proof of a person's identity; firmware changes, spoofing and cloned machines can affect it.

The server indexes accepted reports atomically by identity kind/hash, independently of SteamID64, deduplicates upload retries and retains history for 180 days. It shows up to 20 previous retained reports and permits authorized administrators to open the exact old report. Missing legacy IDs, expired records and index failures never become a claim of a first-ever scan. PDF export uses the same authorized report and includes its evidence, coverage, limitations and repeat-check history.

Native hardware-identity lookup returned `smbios_uuid_v1` in this development session. Offline fixture suite now has 39 checks.


## Signed public releases

`build.ps1` can sign the final EXE with a publicly trusted Code Signing certificate installed with its private key in the Windows CurrentUser or LocalMachine Personal certificate store (including a provider-backed key). Do not put private keys or passwords in this repository.

```powershell
.\build.ps1 -CertificateThumbprint YOUR_CERTIFICATE_THUMBPRINT -RequireSignature
```

The signing step verifies the certificate chain, applies a SHA-256 Authenticode signature with a timestamp, then verifies the final signature. A self-signed certificate is rejected. The receipt is generated **after** signing. Publish the resulting signed executable and update the backend build SHA-256, download URL and file size together; the scanner reports its own hash and must match the server policy. Never reuse the pre-signing hash. Do not replace an existing immutable download object with different bytes.

Without a certificate, the ordinary build remains available for development and emits an unsigned-build warning. `-RequireSignature` prevents an unsigned release. Microsoft Artifact Signing requires a separately configured account, validated publisher identity and service integration; it is not configured by this certificate-store path.

A valid signature identifies the publisher; it does not guarantee immediate SmartScreen reputation or certify the program as malware-free. Do not disable browser/Windows protection or wrap/rename the executable to hide a warning. Microsoft guidance: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation

Verified on 2026-10-14: the currently downloaded 0.6.0 EXE matches the site's SHA-256 and is `NotSigned`. No code-signing certificate was available in either local certificate store. A signed public build remains pending a trusted certificate.

## Scanner 0.7.0 (2026-11-04)

This section supersedes the older collection boundaries above. Running WARDOGS is allowed. New read-only collectors record foreign handles with game access rights, loaded game/Discord DLL metadata with file hashes and offline signature verification, private executable game-memory region counts (no contents), running macro tools and bounded static macro-script features. File names alone do not establish legitimacy or cheating. Macro execution and overlay injection are not proven by these heuristics.

Browser catalog 2026-11-04.1 includes 48 rules and expanded multilingual game-context keywords. Opera GX root, Default and nested side profiles are discovered. Each matching URL includes first/last visit timestamps and count. With explicit browser_matched_urls consent, matched URLs and relevant search queries are exported; authentication parameters, fragments, credentials and unrelated history are excluded. URLs are limited to 2048 characters. Browser matches remain review leads.

Validation: 77 offline fixtures, native synthetic external-access/module checks and backend report-contract tests. No real cheat was executed and real game compatibility remains unverified. Publish the matching backend contract and executable SHA-256 policy together. The development EXE is unsigned unless a trusted signing certificate is supplied.

## Scanner 0.7.1: cmd launch context and file identity

The new process_context collector takes a bounded, read-only Win32_Process snapshot. It checks live parent PID plus creation times, examines interpreter arguments locally, and reads at most eight referenced absolute local script paths per process (512 KB each). It can recognize Python, PowerShell, cmd, AutoHotkey and AutoIt launch context, including interpreter identity retained in version metadata after renaming. PowerShell EncodedCommand is decoded locally as data, never executed. Raw command lines and script contents are not exported. The consent screen now discloses this local analysis.

Steam, OneDrive, Photoshop and Discord names are checked against verified offline Authenticode publishers, original filenames and product metadata. File hashes support manual correlation. Metadata is self-declared and can be forged; a valid on-disk signature does not prove the live process is uninjected. Loaded-module inventory now includes Steam, OneDrive and Photoshop as well as game/Discord processes. No automatic ban follows from these observations.

Coverage remains a snapshot: exited parents, short-lived loaders, unresolvable relative paths, encrypted/obfuscated code, renamed tools with stripped metadata, hardware macros and kernel/DMA activity can remain invisible. A referenced macro script proves a launch reference, not execution of its input code or use in the game. Missing information stays partial.

Validated with 77 existing offline fixtures plus 22 process-context fixtures. The --context-native fixture starts inert copies of the test runner via real cmd.exe: a Steam.exe copy holds a read-access handle to a mock game; a python.exe copy receives a synthetic script path but never executes it. The collector must detect both, verify parent timestamps and omit secret sentinel arguments. Backend focused suite: 32 passing tests. No real cheat sensitivity measurement or real game compatibility claim.

Primary reference: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process (ParentProcessId reuse and CreationDate; reviewed 2026-11-04).

## Scanner 0.7.3: responsive scan progress

ProcessContextCollector previously resumed its analysis on the WPF synchronization context, then synchronously waited for an asynchronous file hash that could need the same UI thread. ProcessCollector also performed signature work on that thread. Both collectors now enter a background task before collection; HashAsync does not capture the caller context. The scan screen updates every second with completed collector count, elapsed time and remaining collectors. This is collector completion progress, not a predicted ETA. Existing 15-minute cancellation remains cooperative for native calls.

Validation: 77 existing fixtures, 22 process-context fixtures, a new blocked-UI synchronization-context hash regression and the native cmd/renamed-host scenario. These tests use synthetic files/processes; they do not establish a fixed scan duration on player PCs. Version 0.7.3 is a client-only correction; publication updates the four scanner metadata fields using the existing server image.
