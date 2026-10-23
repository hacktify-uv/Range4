# M2 NIGCL Contracts — Evidence Bundle

[Red Solution](Red-Solution.md) | [Blue Solution](Blue%20Solution.md)

This archive contains two self-contained Markdown writeups with embedded, user-provided screenshots. Open `Red-Solution.md` and `Blue Solution.md` with a Markdown preview (e.g. VS Code `Ctrl+Shift+V`). Images are referenced using relative paths and should render without moving any files.

## Lab
- Kali: `192.168.222.128`
- M2 Ubuntu/Contracts API: `192.168.222.131:3000`
- M1: `192.168.222.130`

## Contents
- `Red-Solution.md` — official six-stage order, verified commands/results, Flag 2, working Python exploit; M3 pivot deferred
- `m2_jwt_exploit.py` — tested standard-library HMAC adaptation needed for modern PyJWT behavior
- `images/` — captured Kali screenshots
- `Blue Solution.md` — four official detection steps, evidence interpretation, and deferred remediation
- `images/` — captured M2 Ubuntu screenshots

## Accuracy and evidence notes
- No screenshots were invented. No separate `/api` enumeration screenshot was supplied.
- The initial `InvalidKeyError` trace was supplied as terminal text, not a screenshot; it is explained in Red Step 4 without a fabricated image.
- The initial login failure was caused by Node/OpenSSL signing compatibility; the fix is documented.
- The flag file initially lacked read permission for the web service; the deployment fix is documented.
- Blue Step 4 evidence shows 200 responses before later 401/403 responses. Do not label it as chronologically 403 → 200 without obtaining that additional evidence.
- M3 pivot and Blue remediation were not performed. They are marked deferred; no screenshots are available for these steps.
- This bundle contains exercise-only credentials and flag material. Keep it within the authorized cyber-range environment.

Sources:
- https://github.com/hacktifytechnologies/Range4/blob/main/machines/M2-nigcl-contracts/solve_red.md
- https://github.com/hacktifytechnologies/Range4/blob/main/machines/M2-nigcl-contracts/solve_blue.md
