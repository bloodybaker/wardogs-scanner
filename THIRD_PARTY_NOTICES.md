# Third-party inventory — publication review pending

The root MIT license covers original WARDOGS source. It does not relicense
third-party code, fonts, logos or trademarks.

| Component | Required review |
| --- | --- |
| .NET / WPF runtime | Include exact runtime pack license and THIRD-PARTY-NOTICES |
| Microsoft.Data.Sqlite / Core 10.0.12 | Preserve package license notices |
| SQLitePCLRaw bundle/core/provider/native e_sqlite3 2.1.12 | Preserve package notices and SQLite provenance |
| Microsoft.NET.ILLink.Tasks | Check lock-file version and package license |
| Assets/e-Ukraine-Regular.otf and e-Ukraine-Bold.otf | No supplied license: obtain redistribution/embedding rights and assess Foundation compatibility, or replace |
| Assets/wardogs-ua-logo.png | Confirm ownership and redistribution terms |

This is not a completed license audit. `src/Wardogs.Scanner.App/packages.lock.json`
records development dependencies; `packages.publish.lock.json` locks the self-contained release versions and hashes. Include actual upstream license texts
in the release bundle before public distribution. Only the project EXE is
submitted for signing; upstream DLLs are not individually signed as our work.
