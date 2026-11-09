# Third-party notices

Original WARDOGS Scanner source and owner-authored logo are MIT licensed.
Dependencies and fonts retain their upstream licenses. The release ZIP
includes this inventory and the license texts in `licenses/`.

| Component | License and attribution |
| --- | --- |
| .NET runtime 10.0.11 / WPF | MIT; .NET Foundation and contributors; see runtime LICENSE, THIRD-PARTY-NOTICES and WPF LICENSE |
| Microsoft.Data.Sqlite / Core 10.0.12 | MIT; Microsoft Corporation / .NET Foundation and contributors |
| SQLitePCLRaw bundle/core/provider/native e_sqlite3 2.1.12 | Apache-2.0; Copyright 2014-2024 SourceGear, LLC; Eric Sink |
| SQLite engine included by SQLitePCLRaw | Public domain; https://www.sqlite.org/copyright.html |
| Microsoft.NET.ILLink.Tasks 10.0.11 (build only) | MIT; Microsoft Corporation / .NET Foundation and contributors |
| e-Ukraine Regular and Bold | CC BY 4.0; Dmytro Rastvortsev, Fedoriv Agency, Ministry of Digital Transformation of Ukraine; see licenses/e-Ukraine-NOTICE.md |
| WARDOGS logo | MIT; owner authorship confirmed; see licenses/WARDOGS-LOGO.md |

Versions and integrity hashes are recorded in `packages.lock.json` and
`packages.publish.lock.json` under `src/Wardogs.Scanner.App/`. NuGet metadata
declares MIT for Microsoft packages and Apache-2.0 for SQLitePCLRaw.
Runtime notices were copied from the exact 10.0.11 runtime packages.
Upstream sources: https://github.com/dotnet/efcore,
https://github.com/ericsink/SQLitePCL.raw/tree/v2.1.12,
https://github.com/dotnet/runtime, https://github.com/dotnet/wpf.

Fonts are unmodified and match the official Ministry archive byte-for-byte.
CC BY 4.0 is retained for these non-code assets; Foundation eligibility of the
complete bundle remains subject to SignPath review. No claim of Foundation
approval is made. Third-party DLLs are not individually signed as our code.
