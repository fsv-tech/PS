# probes1400 — the door map you run before writing an exploit

Not a jailbreak. A read-only instrument that answers, on your console, the one
question that decides *which* jailbreak is writable: does the aio wait still
sleep, and which doors are open around it.

## Why this exists

Three independent 14.00 efforts stop at the same place — the kernel primitive.
Two of them (`hx1400_port.js`, the BD-J Xlet) stop *before* it by design. The
remaining question is not "how do we write the exploit" but "which of the four
candidate doors is actually ajar on this build". Guessing costs a console
reboot per guess; measuring costs one run.

## Wiring

The module takes the same context object the fork's `hx1400_port.js` already
uses, so it drops in beside it:

```js
import { runProbes } from "./probes1400.js";
import { HX1400_TABLES } from "./hx_tables.js";

const results = await runProbes({
  sc,                      // (num, ...args) -> { i32 }, built on the fcall
  bufAddr,                 // ArrayBuffer -> int64 address
  keepAlive,               // array; buffers must stay reachable
  mark,                    // (tag, detail) -> your log
  errno,                   // optional: () -> current errno
  anchorRva: HX1400_TABLES.P[12],   // ANCHOR, enables kbase derivation
  allowDeviceProbe: false, // set true only when you want the dipsw shot
});
```

`runProbes` never throws past its own boundary; a broken gateway aborts after
`BASELINE` and reports it.

## The browser half

`probes1400.js` is the instrument; these three files are what carries it to a
console:

| file | role |
|---|---|
| `fcall.js` | gadget gate, stub discovery, call gate (`sc` / `bufAddr` / `errno`). Ported from raw13g `jb.js:349-542`, with no imports so it can be tested against a mock `p` |
| `boot.js` | the run order: import chain -> `establishPrimitive` -> `installWindowP` -> bases -> gadgets -> stubs -> gateway -> `runProbes` -> disarm |
| `index.html` | the page: live stage log, verdict table, decision banner, JSON report |

Open it from wherever the chain files are served:

```text
http://<host>:8000/index.html?base=../        # chain next to jb.html (default)
http://<host>:8000/index.html?base=/raw13g/   # chain somewhere else
http://<host>:8000/index.html?auto=0          # load, do not run
http://<host>:8000/index.html?dipsw=1         # arm the one-shot /dev/dipsw probe
http://<host>:8000/index.html?v=2             # bust the chain imports (PS4 caches hard)
```

`?base=` is the only thing that has to be right. Every other parameter is a
debug override and is echoed in the log when used. The page stops at the stage
it could not pass and prints what it saw:

- `import` -- no `core.js` / `mem.js` at `base`, or the page was opened over
  `file://`, where ES modules do not load;
- `firmware` -- no table entry for the UA's firmware, or the entry lacks an
  anchor;
- `bases` -- the two anchors did not land on `0x4000`-aligned addresses, so the
  table is for a different build or the modules moved;
- `gadgets` -- a byte at one of the 15 RVAs is not the gadget; the message names
  it (`LEAVE_RET rva=0x170 byte 0 want=201 got=144`);
- `stubs` -- reported, not fatal: the gateway is built from whatever was found,
  and probes needing a missing stub throw and are recorded as such.

## The 14.00 stub bound

`PS4["14.00"]` sets `k_stubs: undefined` and inherits `k_scan_stage1: 0x40000`
from 13.52 -- no seeds, and a bound measured on a different kernel. So
`discoverStubs()` runs three passes: seeds (none on this build), the declared
window, then a fallback window from `k_scan_stage1` to `min(4x, 2 MB)`, bounded
by a read budget and abandoned on the first fault.

The report keeps those outcomes apart, which is the whole point:

| report | meaning |
|---|---|
| `seeded=.. stage1=..`, `ok` | the table was right |
| `fallback=N (declared window 0x40000 was short)` | the bound is wrong for this build and stubs live past it. **Record N** -- it is the measurement the table is missing |
| `stopped=stage1@0x…/read-fault` | the libkernel base is wrong, not the window |
| `stopped=…/read-budget` | the window was searched as far as the budget allowed |
| `missing=…` with no `stopped` | both windows were searched and the stub is not there |

## Reading the result

| marker | verdict | what it decides |
|---|---|---|
| `AIO-WAIT` | `GATED` | wait returns in <5 ms: no waiter is built, so the aio UAF cannot land. **Delete-TOCTOU is the only aio path left.** |
| `AIO-WAIT` | `SLEEPS` | wait blocks ~= timeout: the Lapse-family door is live on this build. Port it — that is the shortest route to a primitive. |
| `AIO-WAIT` | `AMBIGUOUS` | 5–40 ms. Re-run before concluding; could be scheduling noise. |
| `AIO-DELETE` | `ALIVE` | the handler the TOCTOU needs still runs. |
| `AIO-POLL` | `ALIVE` | queue is functional; submit is producing real requests. |
| `DIPSW-OPEN` | `PASS` | `/dev/dipsw` reachable — the only measured-open device door. |
| `DIPSW-IOCTL` | `ACCEPTED` | first command in the documented window is accepted: a real surface, never published. |
| `SYSCTL-ROUTE` | `PASS` + `KBASE` | leaks kernel base without writes — the prerequisite for any patch. |
| `KBASE` | `UNRESOLVED` | route works but no anchor hit: `anchorRva` is wrong for this build, or the record shape differs. |

## Decision rule

- `AIO-WAIT=SLEEPS` → stop reading, port the public Lapse chain. The rest of
  this is moot.
- `AIO-WAIT=GATED` and `AIO-DELETE=ALIVE` → the target is the lock-upgrade
  window inside `sys_aio_multi_delete`, raced from a worker thread. That is the
  only aio primitive that does not depend on the wait.
- Both closed → `DIPSW-IOCTL` becomes the lead, one command per session.

## Safety posture

- No kernel writes anywhere in the module. No arbitrary-address read of kernel
  memory: the only kernel data touched is the sysctl route buffer.
- The device probe is single-shot (one `open`, one `ioctl`, one `close`) and
  disabled unless `allowDeviceProbe` is explicitly set. No command sweeps.
- Every probe is individually wrapped; a failure reports and continues.
- Buffers are pinned through `keepAlive`; nothing relies on GC timing.

## Verification status

Three suites, all against mocks — no console, no device:

```
node tools/probe.test.mjs     #  8 checks -- verdict logic, mock syscall gateway
node tools/fcall.test.mjs     # 36 checks -- gadget bytes, stub passes, ROP frame
node tools/boot.test.mjs      # 25 checks -- firmware, anchors, decision, stages
```

`fcall.test.mjs` builds a module image whose bytes are whatever the table says,
then checks the gate accepts it, that one flipped byte names the gadget, that G4
follows `pivot_view_sp` in both directions, and that a stub placed past
`k_scan_stage1` is found by the fallback and reported as such. It also asserts
the ROP frame's slot order, the 16-byte alignment of the ret slot, that the
pivot lands on the frame base, that `sc()` puts the borrowed cell back, and that
`bufAddr()` walks cell -> impl -> data. `boot.test.mjs` walks the stage machine
with a fixture chain and proves a zero memory primitive is refused at `bases`
before anything scans from address zero.

The page itself was loaded in a browser against that fixture chain: it reached
`PRIMITIVE-OK`, stopped at `bases`, and showed `NOT 0x4000-aligned` with no
uncaught error. With no chain present it stops at `import` and names `core.js`.

What none of that proves: that the RVAs in the table are right for a 14.00
module. The submit
format (`4097`, op `3`, 40-byte requests) and the sysctl MIB
(`4,17,0,28,1,0`) are inherited from the fork's `wash()` and `discoverKbase()`,
not derived here. If the port's assumptions about those are wrong, the probes
will report `CLOSED` on a door that is actually open — which is why the
`BASELINE` check runs first and why a `CLOSED` verdict on `AIO-DELETE` should be
re-tested before it is believed.
