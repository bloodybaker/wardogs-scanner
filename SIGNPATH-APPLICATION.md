# Application draft — not submitted

Project: WARDOGS Scanner
Website/download: https://wardogs.com.ua/scanner
Source repository: https://github.com/bloodybaker/wardogs-scanner (currently private; make public before applying)
Repository owner: https://github.com/bloodybaker
Application contact: TO COMPLETE
Committers, reviewers, signing approvers: TO COMPLETE (CODE_SIGNING.md)
License: MIT for original source; asset and dependency notices pending review.
Platform: Windows 10/11 x64, .NET 10 WPF, portable self-contained executable.
Current source: 0.7.4; attach verified public release and GitHub CI URLs.

WARDOGS Scanner supports human review of moderation appeals. Users enter a
one-time code and explicitly consent to collection and HTTPS report transfer
to wardogs.com.ua. It inventories processes, executable hashes/publishers,
DLLs, persistence and execution traces, Windows protection state, PCIe
devices, foreign handles and executable memory-region metadata. It locally
examines bounded scripts, interpreter arguments and browser history matches.
Reports include matching URLs/search queries, timestamps, technical paths
and a pseudonymous device hash. Raw commands, scripts, memory contents,
passwords, cookies and unrelated history are not uploaded.

No exploitation, protection bypass, driver installation, injection or security
configuration changes are performed. Findings are not automatic cheating
verdicts. Please assess whether the Windows protection-state/device checks
are eligible under the security-diagnosis restriction.

Privacy is embedded and accessible before scanning. Refusing required consent
prevents collection and report transfer; users can close the portable app.
There is no offline end-user scan mode. Please confirm whether this opt-in
flow meets the privacy/disable requirements.

Proposed pipeline: reviewed source, GitHub-hosted builds, artifact origin
verification, restricted EXE metadata, mandatory manual SignPath approval,
pinned actions, final signature and hash verification. Only the project EXE
is signed, with no separate signing of upstream DLLs. The EXE bundles .NET
and SQLite; please review this packaging during onboarding.

Before submission: complete public links, named roles and asset permissions,
provide CI/release evidence, verify repository ownership and MFA. Acceptance
and production signing are pending; do not claim these steps are complete.
