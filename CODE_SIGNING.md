# Code signing policy

Status: preparation only. No SignPath Foundation approval or signing certificate
has been obtained. Existing downloads must not be described as Foundation-signed.

Releases are built from reviewed source on GitHub-hosted Windows runners.
Only WardogsScanner.exe is submitted; third-party DLLs are not separately signed
with this project's certificate. Each production request requires a human
approver in SignPath. Tokens are stored in a protected GitHub environment, never
in source. MFA is required for repository and SignPath team accounts.

The project owner is responsible for these roles. Production SignPath account
enrollment and signing policy activation remain pending:

| Role | Members |
| --- | --- |
| Authors / committers | [Yevhenii Chykalov (@bloodybaker)](https://github.com/bloodybaker) |
| Reviewers | [Yevhenii Chykalov (@bloodybaker)](https://github.com/bloodybaker) |
| Signing approvers | [Yevhenii Chykalov (@bloodybaker)](https://github.com/bloodybaker) |

Privacy policy: [PRIVACY.md](PRIVACY.md). Reports go to WARDOGS only after
explicit consent and starting a scan. There is no offline end-user scan mode.

After Foundation acceptance, add this attribution to the project home and
download/release pages, together with a link to this policy:

> Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

This attribution is pending and is not a claim of current sponsorship.
The release process rejects invalid, untimestamped or unexpected certificates.
Hashes are computed from the final signed bytes. A valid signature does not
guarantee SmartScreen reputation or establish that a scan result is correct.
