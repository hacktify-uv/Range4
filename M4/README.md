# M4 NIGCL Scheduler — Red & Blue Evidence Bundle

[Red Solution](Red-Solution/README.md) | [Blue Solution](Blue-Solution/README.md)

This package contains tested writeups with screenshots from 23 October 2026, mapped into the corresponding sections.

- `Red-Solution/README.md`: official Red steps 1–8; M5 pivot deferred
- `Blue-Solution/README.md`: official Blue detection steps 1–4; remediation deferred
- Image files are referenced by relative paths and should display in GitHub or VS Code Markdown Preview.

## Evidence inventory

**Red Team:** 10 images. **Blue Team:** 6 images. **Total:** 16 images.

## Notes

The initial auditd installation was missing and later corrected. The later auditd write event reflects a harmless comment append made after the watch was added, not the original malicious payload append. Observed SUID execution and successful effective root are independently documented.

The IPs and secrets in these writeups belong to the user's isolated lab. Do not expose these intentionally insecure services to the public internet.

Sources:
- https://github.com/hacktifytechnologies/Range4/blob/main/machines/M4-nigcl-scheduler/solve_red.md
- https://github.com/hacktifytechnologies/Range4/blob/main/machines/M4-nigcl-scheduler/solve_blue.md
