# 14.00 experiment bundle

This is raw13g's chain wearing a `14.00` label. **No 14.00 number in here was
measured.** The entry is a verbatim copy of the 13.52 table with `alias_of:
"13.52"` and a `fw_status` that says so. Run it knowing that.

It exists so the hypothesis can be tested on hardware instead of argued about.

## What is actually hypothesised vs known

| | status |
|---|---|
| 22 WebKit RVAs (`wk_*`) | **measured** for 13.00–13.52 (identical across all five). Hypothesis: 14.00 did not rebuild `libSceWebKit2`. |
| 20 kernel RVAs (`k_*`) | **measured** for 13.52 only. Hypothesis: **weak** — 7 of 20 already moved inside the 13.x line. Assume these are wrong. |
| `kpatch` | `1352.bin` — the 13.52 patch blob. Will write to 13.52 addresses. |
| `payload` | `payload2.bin` (PS4-HEN, works ≤13.52). |

The WebKit half is a testable bet with evidence behind it. The kernel half is
not a bet, it is a guess, and guesses there do not fail politely.

## Run it

Serve the directory (ES modules need HTTP, `file://` will not work):

```
cd C:\Users\james\Desktop\Hen\14.00-EXPERIMENT
python -m http.server 8000
```

On the PS4 browser, same Wi-Fi, open:

```
http://<your-pc-ip>:8000/jb.html?stage=webkit&verbose=1&log=1
```

`stage=webkit` is a guard I added to `jb.js`: it returns immediately after the
primitive is installed, **before any kernel pointer is dereferenced**. No kernel
write, no kpatch, no payload. This is the run that answers the only question
worth answering today:

- **`WEBKIT OK -- stopped at stage=webkit`** → 14.00's `libSceWebKit2` is the
  13.x build. The 22 WebKit numbers are correct on your console, and the only
  thing standing between you and a chain is the kernel table. That is a real
  result and it would be the first one anyone has.
- **The tab dies / "memory could not be read" / the browser closes** → the
  WebKit build moved. The primitive crashed the renderer, which is what a
  renderer process is for. Relaunch the browser; nothing persists.
- **Nothing renders at all** → the engine is too old for this file (it uses
  modules, `async`, arrow functions). That is `caps.html`'s job to tell you
  first, not this page's.

## Then, if you still want the full run

```
http://<your-pc-ip>:8000/jb.html?verbose=1&log=1
```

No `stage=webkit` means it continues: kernel base from `k_idt_rsvd`, sysent
hijack, `1352.bin`, `payload2.bin`. On a 14.00 kernel those addresses are
almost certainly not what they were on 13.52.

Expected outcome: kernel panic, black screen, console restarts. Possible
outcome: it hangs and needs the power cable. You said you accept that; this
paragraph is the receipt.

Recovery, in order: hold power ~10s to force off → restart → if it boots, stop
and take the `stage=webkit` result as your data point. If it does not boot,
safe mode (hold power until the second beep) → rebuild database → if that
fails, you are reinstalling the firmware, and 14.00 is not downloadable from
Sony for much longer than they keep it up.

## Do not publish this folder

`jb.js`, `core.js`, `mem.js`, `int64.js`, `payload2.bin` and `patches/*.bin`
are raw13g's work, and his LICENSE explicitly keeps the primitive files and the
payload blobs under their own terms. Running them locally is fine. Putting them
in your public repo is redistributing someone else's exploit code under your
name — keep them out of `raw14g-public`, which is why that repo's `.gitignore`
blocks `*.bin` and `*.jar`.

## What would make this real

One dump from a running 14.00 console: `kernel_1400.elf` and
`libSceWebKit2.sprx`. Then

```
python tools/derive_offsets.py --ref <13.52 webkit> --target <14.00 webkit> \
                               --table tools/ref/offsets_1352.json --js
python tools/kpatch_regen.py --retarget tools/ref/1352.bin sites_1400.json
```

and the numbers stop being a hypothesis. That is the whole distance between
this folder and `raw14g`'s gate saying `TABLE OK`.
