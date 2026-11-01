RAW 14.00 - VERIFIED DIAGNOSTIC HOST
====================================

This archive is a firmware-detection / measurement-checklist host, NOT a PS4
jailbreak and NOT a HEN/GoldHEN payload. It does not enable homebrew on firmware
14.00.

Verified locally on the included test suites:
- node tools/test.mjs
- node --test probe/tools/*.test.mjs

All included checks passed in the packaging environment. These are unit/mock
tests; they do not establish compatibility on a physical PS4.

Run locally:
1. Extract this archive.
2. Open a terminal in the extracted raw14g folder.
3. Run: python -m http.server 8000
4. Open: http://localhost:8000/

The host should identify firmware 14.00 and report NO MEASURED TABLE. This is
intentional. The required 14.00 WebKit/kernel offsets, kernel patch and payload
are absent. Do not fill the table with guessed values or force-launch it.

No BD-J image or remote-reporting ISO is included in this archive.
