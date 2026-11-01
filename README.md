# raw14g — a raw13g-shaped host, gated on a measured 14.00 table

## What this is

The front end that raw13g's site has and 14.00 does not: firmware detect,
kernel-table gate, measurement checklist. It is deliberately **not** a
jailbreak. `jb.html` is a stub, because no 14.00 WebKit chain exists to ship.

## What `hen.iso` actually is

| item | value |
|---|---|
| container | UDF 2.60, 6,225,920 bytes, volume id `BONKHEN` (burned with Microsoft IMAPI2) |
| content | one BD-J Blu-ray Java title (a jar), no ISO9660 bridge, no game data |
| jar | `META-INF/MANIFEST.MF`, `SIG-BD00.SF`, `SIG-BD00.RSA` + `bonk/` + `org/bdj/` |
| payload | `bonk/hen.bin`, 562,240 B, raw x86-64 blob (`e9 a6 4a 00 00` jmp, then `endbr64`) — not an ELF |
| data | `bonk/local/*.bin` — custom tables `FMW1` (write sites), `FMM1` (marker sites), `FMG1` (guards), `FMC1` (schedule), plus 40 `cmd-XXXX.bin` templates |
| code | `org/bdj/{Boot,InitXlet,Screen,OfflineRenderer,LocalResultLedger,Cfg}.class` |

Self-description found in the image: `Bonk HEN 14.00 local HEN review candidate`.
Runtime strings: `uid=0, patch the kernel, then load and launch hen.bin`,
`kernel is stock - 1400.bin will be applied`, `syscall 11 IS NOW kexec`,
`/data/hen/hen.ini`, `/data/hen/plugin_loader.prx`, `/user/temp/hen.installed`.

**It is a BD-J path, not a WebKit path.** The Xlet never touches the browser.

## Two things worth knowing before you share this image

1. `org/bdj/Cfg.class` hardcodes `SERVER = http://tester.f5rvoice.com:1992`
   and `Boot.class` posts to it with an `X-Ticket` header plus the key
   `942a76d6946a34ce476bdabb09989f4c`. A HEN that reports to a remote host is
   not something to run on a console you care about, whatever else it does.
2. The jar is BD-signed (`SIG-BD00.RSA`). Adding any file to it invalidates
   that signature. Repacking is fine for testing on a console that ignores BD-J
   JAR signing; it is not a drop-in patch for a retail disc.

## Why there is no 14.00 chain in here

The raw13g chain is one code path (`jb.js`) plus a per-firmware table. Its
`ps4_offsets.js` contains exactly: `11.00, 11.50, 12.00, 12.50, 13.00, 13.02,
13.04, 13.50, 13.52`. Its `patches/` contains `1302.bin`, `1350.bin`,
`1352.bin`. There is no `14.00` entry, no `1400.bin`, no 14.00 measurement, and
the newest public WebKit release is 13.52.

To make a 14.00 entry real you need, per key in `fwtable.js`:

- 13 WebKit-module RVAs (ROP gadgets) + `wk_expm1_builtin`, `pivot_view_sp`,
  `wk_ArrayBuffer_*` struct offsets and `wk___imp___error`, measured from the
  **14.00** WebKit module;
- 7 kernel RVAs (`k__error`, `k_scan_stage1/2`, `k_evf_cv`, `k_sysent_661`,
  `k_jmp_rsi`, `k_idt_rsvd`) measured from a **14.00** kernel image, the way
  13.50 was measured (`kdump -> rebase vs tier0 -> derive vs tier1 -> adversarial
  re-check`);
- a 14.00 kernel patch blob and a payload that works on 14.00.

None of that is derivable from the ISO, and none of it is public. Writing
plausible numbers here would produce a page that looks finished and corrupts a
console on first run, which is worse than shipping nothing.

## What is done and verified

```bash
node tools/test.mjs      # 11 checks, all pass
```

- `index.html` — UA detect (`PlayStation 4/(\d+)\.(\d+)`, minor read as hex),
  table lookup, gate; refuses and routes to the checklist instead of launching.
- `fwtable.js` — same `REQUIRED_KEYS`/`OPTIONAL_KEYS` contract as
  `ps4_offsets.js`, so a measured table drops in without touching the host.
  `PS4["14.00"]` is present, `measured: false`, every offset key absent.
- `gate.js` — rejects missing, zeroed, out-of-range and half-filled entries.
- `measure.html` — per-key checklist with the source of each measurement and a
  JSON skeleton to fill in.
- `tools/test.mjs`, `tools/rebuild_jar.py`.

## Finishing it

1. Measure the 27 keys on a 14.00 unit and build `patches/1400.bin`.
2. Fill `PS4["14.00"]` in `fwtable.js`; drop `jb.js`, `core.js`, `mem.js`,
   `int64.js` and `patches/` beside `jb.html`.
3. `node tools/test.mjs` — the gate flips to `ready` only when the table is whole.
4. `python tools/rebuild_jar.py` writes `hen-repacked.jar` with the host already
   inside at `bonk/webkit/`; rebuild the disc image with `oscdimg` (UDF, volume
   label `BONKHEN`) or any UDF 2.60 writer.

Local preview needs HTTP, not `file://`, because the host uses ES modules:

```bash
python -m http.server 8000    # then open http://localhost:8000/
```

Append `?force=1` to see the forced path — it lands on the stub, not a chain.
