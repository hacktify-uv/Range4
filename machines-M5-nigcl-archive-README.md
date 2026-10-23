# M5 NIGCL Archive — Evidence Package

**Contents:** `solve_red.md`, `solve_blue.md`, and `screenshots/` with real user-provided screenshot captures from the 23 October 2026 exercise.

**Deployment:** Ubuntu 22.04.5 VM `nigcl-archive`, IP 192.168.222.134; attacker Kali at 192.168.222.128.

**Outcome:** Path traversal in the root-owned SUID `safereader` disclosed Flag 5. Blue Team auditd detected SUID invocation and a protected-file read with `auid=archivist`, `euid=root`.

**Important:** Red Team optional `/etc/shadow` access and remediation were not performed. No evidence has been fabricated.

Open the Markdown files in VS Code preview (`Ctrl+Shift+V`) to view inline screenshots. Paths are relative and work after extracting this complete archive.
