# 14.00 reality check — what I fixed, what no edit can fix

Read this before you burn another disc.

## Bottom line

1. **The host page now actually runs on a PS4.** It used ES modules, `async`,
   arrow functions and `URLSearchParams`. The PS4 system browser is a 537.x
   WebKit — none of that exists there, so on your console the page did not
   detect firmware, did not draw, and did not error visibly. It now does.
2. **Fixing that does not produce a jailbreak, and no file edit can.** The gate
   is not the bug. The table is empty because the 14.00 numbers do not exist —
   and the two "14.00" offset files sitting in `_research/candidates/` are
   arithmetic, not measurements (§2). Filling them in makes the page look
   finished and corrupts the console on the first kernel write.
3. **The `hen.iso` in this workspace phones home and executes what it gets
   back.** That is a bigger problem than the offset gap, and it is fixable
   (§4).

---

## 0. Measured on the console — 2026-11-01

`caps.html` on a stock 14.00 unit:

```
CAPS|webkit=605.1.15|bigint=1|worker=1|wasm=0|proxy=1|yes=25/30
```

| probe | result | consequence |
|---|---|---|
| `AppleWebKit` | **605.1.15** | 14.00 is *not* the 537.x engine that 13.x ships. The "frozen engine, inherit 13.52 RVAs" premise in `docs/01-entry-ssv/frozen-engine.md` is measured false. |
| BigInt / BigInt literal / BigInt64Array | yes | the SSV bug class is not ruled out by absence — whether that bug survives in 605.1.15 is untested |
| Web Worker | yes | the `aio_multi_delete` TOCTOU lead (needs two concurrent syscall streams) stays open |
| WebGL 1 / WebGL 2 | **no** | the canvas/WebGL OOB surface is gone |
| WebAssembly | **no** | the WASM surface is gone |
| SharedArrayBuffer | **no** (Atomics present but useless without it) | shared-memory threading tricks are out |
| hardwareConcurrency | **4** | contradicts the "browser gets cores 6-7" note in `candidates/main__STATUS.md` |

Two of those change the plan rather than refine it: the engine is a different
major WebKit, and three of the usual exploit surfaces are switched off. This is
not a port job.

---

## 1. What was broken for the console, and is now fixed

`index.html` and `measure.html` were written as `<script type="module">` with
`import`, `const`, arrow functions, `async`/`await`, template literals and
`new URLSearchParams(...)`.

Reference point: the working 13.x host (`_research/raw13g/index.html`, 24 KB)
contains **zero** occurrences of `type="module"`, `import `, `=>`, `const` or
`let`. It is strict ES5 — deliberately. That is the only reason it runs on a
console at all. The 14.00 host, and the whole `probe/` door-map, dropped that
discipline and inherited desktop-browser features.

| file | before | now |
|---|---|---|
| `index.html` | module script, no CSS fallback, no output on console | ES5, self-contained, works over `http://` **and** `file://` |
| `measure.html` | module script | ES5, same checklist, renders on console |
| `gate.js` | a complete table with `measured:false` returned `ok:true` | refuses anything that is not `measured:true` |
| `fwtable.js` | `PS4["14.00"]` carried a stray `missing:` field outside the schema | removed; the gate names the gaps itself |
| `tools/test.mjs` | 11 checks | 26 checks, including inline-vs-module parity |

The fix is not cosmetic: the inlined gate in both pages is now tested against
`gate.js` on seven fixtures, so the console build cannot silently drift from
the module build, and a lint step fails the suite if anyone reintroduces a
module script, an arrow, `async`, a template literal or `URLSearchParams`.

```
cd raw14g
node tools/test.mjs
# ALL CHECKS PASSED   (26 checks)
```

On the console, `index.html` now reports:

```
RAW14|fw=14.00|webkit=537.73|gate=unmeasured|missing=27|ready=0
```

That single line is the whole state of the project in one screenshot.

### The gate hole that was real

`gate.js` checked "no key missing, no key out of range" and then returned
`ok: true` — **without ever asking whether the entry was measured**. So the
exact failure mode this project exists to prevent (paste someone else's
numbers in, flip nothing else, launch) passed the gate. It now requires
`measured === true` on the success path, and `test.mjs` covers both
`measured:false` and a missing `measured` flag.

---

## 2. Why the 14.00 table cannot be filled from what is in this workspace

Two files in `_research/candidates/` claim to be 14.00 WebKit data. They
describe the same module and they disagree — uniformly, by exactly one page.

| gadget | `_research/raw13g/ps4_offsets.js` **13.52** (measured, shipped) | `candidates/offsets__webkit-1400.md` "14.00" | `candidates/main__webkit_gadgets_1400.js` "14.00" |
|---|---|---|---|
| `wk_expm1_builtin` | `0x2586880` | `0x2586880` | — |
| `wk_POP_RDI_RET` | `0x5c480` | `0x5c480` | `0x60480` **+0x4000** |
| `wk_POP_RSI_RET` | `0x6e45e` | `0x6e45e` | `0x7245e` **+0x4000** |
| `wk_POP_RDX_RET` | `0x12c5ba` | `0x12c5ba` | `0x1305ba` **+0x4000** |
| `wk_POP_RCX_RET` | `0x1bade` | `0x1bade` | `0x1fade` **+0x4000** |
| `wk_POP_RAX_RET` | `0x10504` | `0x10504` | `0x14504` **+0x4000** |
| `wk_LEAVE_RET` | `0x182f7` | `0x182f7` | `0x1c2f7` **+0x4000** |
| `wk_MOV_QWORD_PTR_RDI_RAX_RET` | `0x548b` | `0x548b` | `0x948b` **+0x4000** |

Read what that says:

- The "14.00, verified live on 14.00" document is **the 13.52 row, relabelled**.
  Byte for byte, all seven gadgets and the base anchor.
- The other file is that same row **shifted by one 0x4000 page on every single
  gadget**. A uniform page shift across seven unrelated RVAs is the signature
  of addition, not of reading bytes out of a module. Seven independent gadgets
  do not all move by exactly `0x4000` when a binary is recompiled.

The rest of that file says so itself, in its own header:

```
// PS4 Kernel Offsets - Firmware 14.00 (PROVISIONAL / UNVERIFIED)
// Notice: Previous offsets were synthetically generated and require byte-pattern validation.
// Kernel panic hazard if uniform deltas (+0x350) are executed.
```

The kernel half was no better. `offsets__kernel-1400.md` says
`SYSENT = 0x1102B70` and explicitly warns that the `0x110A760` circulating
elsewhere is the 13.52 value; `main__1400_offsets.txt` says
`SYSENT = 0x0110A760 (Carried from 13.52; DO NOT revert to 13.04 0x01102B70)`.
One of those two sentences is wrong.

**Update 2026-11-01 — it is now decided, and against the second one.** `bonk/hen.bin`
carries a symbol block at `0x11180`, six u32 fields wide, and it agrees with
`offsets__kernel-1400.md` on every shared entry:

```
0x011180  c0 01 00 00  18 fa 11 01  90 6e 13 02  00 0d 52 01
          XFAST_SYSCALL 0x1c0   PRISON0 0x111fa18   ROOTVNODE 0x2136e90   M_TEMP 0x1520d00
0x011190  c8 d6 53 01  38 85 b2 01  50 73 64 02  80 c0 65 02
          0x153d6c8      ALLPROC 0x1b28538   0x2647350    0x265c080
0x0111b0  c0 42 65 02  70 2b 10 01  60 40 39 00  40 38 0a 00
          FPU_CTX 0x26542c0   SYSENT 0x1102b70   0x394060    _sx_xlock 0xa3840
0x0111c0  00 3a 0a 00  20 95 00 00  e0 96 00 00  70 cb 21 00
          _sx_xunlock 0xa3a00  malloc 0x9520   free 0x96e0   0x21cb70
```

`SYSENT = 0x1102B70`, and `_sx_xlock`, `_sx_xunlock`, `malloc`, `free`,
`XFAST_SYSCALL` all match the "known stable" list in `main__1400_offsets.txt` too.
So the **kernel** numbers here are corroborated by a compiled artifact and should
be treated as good. The **WebKit** numbers are still the 13.52 row with a page
added, and the engine is still 605.1.15. Do not let the one contaminate the other.

And `_research/brstation/1400.bin` — the "1400 kernel patch blob" — is a
632-byte file that differs from `1352_ref.bin` in 99 bytes. The first
differences are displacement operands:

```
1352_ref.bin  ... 66 89 81 a3 77 1b 00   mov word [rcx+0x1b77a3], ax
1400.bin      ... 66 89 81 43 7a 1b 00   mov word [rcx+0x1b7a43], ax
                                                 ^^^^ +0x2a0
```

`+0x2a0` is precisely the "structural drift `+0x2a0..+0x300`" the kernel notes
claim. That is a blob rebased by arithmetic, not a patch built from a 14.00
dump.

**None of this is a reason to be impressed.** `raw13g`'s own table shows
13.00 → 13.52 moving the same gadget from `0x2445241` to `0x5c480` — nine
megabytes. So "the engine is frozen, so 13.52 RVAs still hold" is contradicted
by the very table it would inherit from. You cannot alias, add a delta, or
extrapolate your way to a 14.00 RVA. You read it off the module, or you do not
have it.

### And the table is not the hard part

Your own gates measurement (`candidates/main__STATUS.md`, `docs/06`) says the
public aio chain cannot land on 14.00 at all: `aio_multi_wait` (663) returns in
~4–6 ms at both 1 ms and 100 ms timeouts, so no waiter is ever built and the
reclaim has nothing to hit. The open lead there is the `aio_multi_delete`
lock-upgrade TOCTOU, which is a *kernel primitive you do not have yet*.

Order of operations, therefore: **primitive first, table second.** A finished
`PS4["14.00"]` with no kernel primitive gets you a chain that computes correct
addresses and then has nowhere to go. A kernel primitive with no table gets you
nothing either — but it is the half that is actually missing, and it is not
something a page edit can supply.

---

## 3. Firmware 14.00 keys — what a real table needs

28 required keys, listed in `fwtable.js`. To fill them you need:

- **WebKit (21 keys)** — RVAs from a 14.00 `libSceWebKit2` (the 15 ROP gadgets,
  `wk_expm1_builtin`, `pivot_view_sp`, the `ArrayBuffer`/`JSFunction` struct
  offsets, `wk___imp___error`). Read the bytes at every RVA and check the
  signature before the key goes in the table — `probe/fcall.js` already does
  exactly this at runtime and will name a bad gadget by its expected byte.
- **Kernel (7 keys + optional `k_idt_rsvd`)** — `k__error`, `k_scan_stage1/2`,
  `k_evf_cv`, `k_sysent_661`, `k_jmp_rsi`, from a 14.00 kernel image, the way
  13.50 was measured: dump → rebase against tier0 → derive against tier1 →
  adversarial re-check.
- **A 14.00 kpatch blob and a payload that runs on 14.00.**

When you have them, the table drops in without touching the host: fill
`PS4["14.00"]` in `fwtable.js`, set `measured: true`, and the gate flips to
`ready`. `measure.html` emits the exact skeleton to fill.

---

## 4. The disc is the thing I would not run

`hen.iso` is a BD-J Blu-ray title, and the jar inside it carries a live
network endpoint in two class constant pools. This is read straight out of the
extracted bytes, not inferred:

`org/bdj/Cfg.class` (429 bytes) — four constants:

| constant | value |
|---|---|
| `SERVER` | `tester.f5rvoice.com` |
| `PORT` | `1992` (`0x7c8`) |
| `BUILD` | `6` |
| `CKEY` | `942a76d6946a34ce476bdabb09989f4c` |

`org/bdj/Boot.class` (14,533 bytes) references, in its constant pool, the full
download-and-run stack:

```
java/net/URL, openConnection, "POST", "X-Ticket", setDoOutput,
getOutputStream, write, flush, getResponseCode, getInputStream, read,
java/io/ByteArrayOutputStream, toByteArray,
readUnsignedByte, readLong, readFully,          <- parse the reply
Class.forName, loadClass, newInstance, getMethod, invoke,
getDeclaredConstructor, setAccessible,           <- instantiate what came back
org/dvb/lang/DVBClassLoader, java/lang/reflect/Array,
java/util/Vector, java/lang/Thread, org/bdj/Boot$1
```

plus the request template `http://tester.f5rvoice.com:1992/n?s=`.

That is not telemetry. It POSTs a ticket, reads the reply, parses it into
objects, loads a class and invokes it — a remote-control channel into the
Blu-ray JVM, over plain HTTP, keyed with a constant that anyone with a copy of
this jar also has. Whatever the author intended, *whoever answers on that host
decides what your console runs next.* The domain is not yours, is not
TLS-terminated, and is not reachable by any 14.00 code path you can audit.

Two ways to deal with it, in order of preference:

1. **Do not run it.** Nothing in this package needs that ISO.
2. **If you must look at it, run the neutered copy.** `tools/neutralize_beacon.py`
   rewrites the two host strings in place — byte-length identical, so the class
   files stay structurally valid and every other file, including `hen.bin`, is
   untouched:

   ```
   python tools/neutralize_beacon.py
   # patched  Cfg.class: 0x00dd  tester.f5rvoice.com -> localhost.invalid.x
   # patched  Boot.class: 0x0d64  http://tester.f5rvoice.com:1992 -> http://localhost.invalid.x:1992
   # verified  no 'f5rvoice' left anywhere in the tree
   # verified  bonk/hen.bin sha256 unchanged
   # wrote     hen-neutered.jar  (191,830 bytes, 72 entries)
   ```

   `.invalid` is reserved (RFC 2606), so the lookup fails in the resolver and
   nothing leaves the console. **The repack invalidates `SIG-BD00.SF|RSA`**, so
   this jar is unsigned and will only run where BD-J signature checking is off.

`X-Ticket` and `CKEY` are left in place on purpose — a header name and an
application key are not addresses, and blanking them would only damage the
class files for no gain.

### It is a payload, not an entry

Worth being blunt about, because it is the reason this disc cannot be "made to
work" by editing it: to run `hen.bin` — a raw x86-64 blob — at `uid=0`, the
Blu-ray Java Xlet must already be able to execute native code with kernel
access. The Xlet's own strings describe that state as a given:

```
uid=0, patch the kernel, then load and launch hen.bin
kernel is stock - 1400.bin will be applied
syscall 11 IS NOW kexec
```

Nothing in the image produces that state. There is no BD-J → native bridge on a
retail console, and no public PS4 BD-J sandbox escape exists. So the disc is the
second half of a chain whose first half is missing — and its kernel patch is
`1352.bin` rebased by `+0x2a0`, which assumes the 14.00 kernel is a uniform
displacement of 13.52 across all 81 write sites. If that assumption is wrong
anywhere, it writes into kernel `.text` and the console does not come back.

---

## 5. What I would do next, in this order

1. Open `index.html` on the 14.00 console and screenshot the `RAW14|...` line,
   then open `caps.html` and screenshot the `CAPS|...` line. Between them they
   settle the "frozen engine" premise before anyone spends another hour on
   aliasing: the SSV entry is a BigInt pooling bug, so `bigint=0` falsifies that
   entry on this build, and `bigint=1` under a `537.x` UA proves the UA string is
   a fixed label rather than the engine version. Both readings kill the argument
   that 13.52 RVAs carry over — for opposite reasons.
2. Decide the primitive, not the table. `probe/` is a good instrument and it
   is honest about what it cannot prove — but it needs the memory primitive to
   run, so it cannot be step one. The `dipsw` ioctl window and the
   `aio_multi_delete` TOCTOU are the two leads your own notes rank highest.
3. Only when a primitive exists, measure the 28 keys — against that build, and
   verify every gadget's bytes as they go in.
4. Leave the disc alone, or use `hen-neutered.jar`.

I did not invent a single offset for this. That is the whole point of the gate,
and it is the reason the page says `NO MEASURED TABLE` instead of showing you a
progress bar.
