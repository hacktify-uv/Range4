# M3 NIGCL Gateway — Evidence Package

This archive contains two Markdown walkthroughs based on the official Range4 M3 Red and Blue solutions, with evidence from the October 23, 2026 Kali and Ubuntu sessions.

## Files

- `Red-Team/solve_red.md` — SSH → sudo enumeration → Vim escalation → Flag 3 → M4 hint; M4 pivot deferred.
- `Blue-Team/solve_blue.md` — sudo log detection, auditd root-execution evidence, IOCs; remediation deferred.
- `Red-Team/images/` — 7 screenshots.
- `Blue-Team/images/` — 5 screenshots.

## Snapshot and safety notes

- VM IP: `192.168.222.132` (M3); Kali: `192.168.222.128`.
- These files document an intentionally vulnerable isolated training environment.
- Avoid publishing challenge flags and credentials outside authorized teaching materials.
- `195.0.0.0/8` is not inherently a private network; no M4 scan was performed or claimed.
- Original upstream auditctl syntax was corrected in the working commands; original guide linked in both Markdown files.

## Evidence index

### Red Team
- `RED-01A-SSH-Port-Discovery.png` — 06:58:26 screenshot identifier.
- `RED-01B-SSH-Authentication.png` — 06:59:03 screenshot identifier.
- `RED-01C-SSH-Session.png` — 06:59:11 screenshot identifier.
- `RED-02-Sudo-Permissions.png` — 07:00:36 screenshot identifier.
- `RED-03-Root-Escalation.png` — 07:02:54 screenshot identifier.
- `RED-04-Flag3-Retrieval.png` — 07:04:23 screenshot identifier.
- `RED-05-M4-Hint.png` — 07:04:34 screenshot identifier.

### Blue Team
- `BLUE-01-Sudo-Vim-Auth-Log.png`
- `BLUE-02A-Auditctl-Missing.png`
- `BLUE-02B-Root-Exec-Audit-Log.png`
- `BLUE-02C-Vim-Bash-Chain.png`
- `BLUE-03-IOC-Summary.png`

## Preview

Open `solve_red.md` or `solve_blue.md` in VS Code, then press `Ctrl+Shift+V`. Image references resolve relative to their own Markdown files.
