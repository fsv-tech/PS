// Exercises fcall.js against the flat memory in mock-memory.mjs.
//
// What this proves: the gadget gate reads the right bytes and rejects the right
// ones, stub discovery actually finds stubs past the declared window (the 14.00
// case), every scan exit reports where it stopped, and the call gate builds the
// frame the ROP entry expects. What it does not prove: that any of the RVAs are
// correct for a real 14.00 module. That needs the console.
import {
  gadgetTable,
  verifyGadgets,
  discoverStubs,
  buildCaller,
  stubNumber,
  stubBytes,
  errnoAt,
  looksAligned,
} from "../fcall.js";
import { makeImage, mem, I64 } from "./mock-memory.mjs";

let fails = 0;
function expect(name, cond, detail) {
  if (cond) console.log("ok   " + name);
  else {
    fails++;
    console.log("FAIL " + name + (detail ? "  -> " + detail : ""));
  }
}

// A table with every key the port needs, at made-up but distinct RVAs.
function baseTable(over) {
  return Object.assign(
    {
      fw_status: "state=TEST",
      wk_expm1_builtin: 0x198000,
      wk_JSFunction_m_function: 0x28,
      wk___imp___error: 0x1000,
      k__error: 0x4000,
      k_scan_stage1: 0x40000,
      pivot_view_sp: 0x38,
      wk_ArrayBuffer_m_impl: 0x10,
      wk_ArrayBuffer_m_contents_m_data: 0x10,
      wk_POP_RDI_RET: 0x100,
      wk_POP_RSI_RET: 0x110,
      wk_POP_RDX_RET: 0x120,
      wk_POP_RCX_RET: 0x130,
      wk_POP_R8_RET: 0x140,
      wk_POP_R9_RET: 0x150,
      wk_POP_RAX_RET: 0x160,
      wk_LEAVE_RET: 0x170,
      wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x180,
      wk_MOV_RDI_RSI_30_CALL: 0x190,
      wk_POP_RAX_MOV_RAX_JMP_18: 0x1a0,
      wk_PUSH_RBP_MOV_RBP_RSP_10: 0x1b0,
      wk_MOV_RDI_RAX_8_CALL_20: 0x1c0,
      wk_MOV_RDX_RAX_18_CALL_10: 0x1d0,
      wk_PUSH_RDX_POP_RSP_RET: 0x1e0,
    },
    over || {},
  );
}

// Lays the gadget bytes into an image exactly as the table says they are.
function moduleImage(off, size) {
  const img = makeImage(size || 0x1000);
  const m = mem(img);
  for (const entry of gadgetTable(off)) {
    const key = entry[1];
    const pat = entry[2];
    const rva = off[key];
    for (let i = 0; i < pat.length; i++)
      if (pat[i] !== null) m.write1(m.at(rva + i), pat[i]);
  }
  return m;
}

function kernelImage(placements, size) {
  const img = makeImage(size || 0x60000);
  const m = mem(img);
  for (const pair of placements) m.poke(m.at(pair[0]), stubBytes(pair[1]));
  return m;
}

// ------------------------------------------------------------------ gadgets

const off = baseTable();
const m = moduleImage(off);
const gate = verifyGadgets(m, off, m.at(0));
expect("gate accepts a clean module", gate.ok && gate.gated === 15 && gate.total === 15,
  gate.gated + "/" + gate.total);
expect("gate keeps every address", Object.keys(gate.addr).length === 15);

m.write1(m.at(off.wk_LEAVE_RET), 0x90);
const broken = verifyGadgets(m, off, m.at(0));
expect("one wrong byte fails the gate", broken.ok === false && broken.gated === 14,
  JSON.stringify({ gated: broken.gated }));
expect("the failing gadget is named", broken.bad.length === 1 && broken.bad[0].name === "LEAVE_RET",
  broken.bad.map((b) => b.name).join(","));
expect("the failure reports the byte it found",
  broken.bad[0].at === 0 && broken.bad[0].got[0] === 0x90 && broken.bad[0].want[0] === 0xc9,
  JSON.stringify(broken.bad[0].got));

// G4 embeds the stack-pivot offset. A table and a module that disagree must not
// quietly pass: that is how you pivot into the wrong field.
const off40 = baseTable({ pivot_view_sp: 0x40 });
const m40 = moduleImage(off40);
expect("G4 follows pivot_view_sp in the table",
  verifyGadgets(m40, off40, m40.at(0)).ok === true);
const crossed = verifyGadgets(m40, off, m40.at(0));
expect("a pivot offset that disagrees fails G4",
  crossed.ok === false && crossed.bad.length === 1 && crossed.bad[0].name === "G4",
  crossed.bad.map((b) => b.name).join(","));

const offNoRva = baseTable();
delete offNoRva.wk_POP_RAX_RET;
const noRva = verifyGadgets(m, offNoRva, m.at(0));
expect("a missing rva is reported, not read as 0",
  noRva.ok === false && noRva.bad.some((b) => b.name === "POP_RAX_RET" && b.reason === "no rva in the table"),
  JSON.stringify(noRva.bad.map((b) => b.reason)));

// ------------------------------------------------------------------ stubs

const s20 = new I64(
  (stubBytes(20)[0] | (stubBytes(20)[1] << 8) | (stubBytes(20)[2] << 16) | (stubBytes(20)[3] << 24)) >>> 0,
  (stubBytes(20)[4] | (stubBytes(20)[5] << 8) | (stubBytes(20)[6] << 16) | (stubBytes(20)[7] << 24)) >>> 0,
);
expect("stubNumber decodes 20", stubNumber(s20) === 20, String(stubNumber(s20)));
expect("stubNumber rejects a wrong tail",
  stubNumber(new I64(s20.low, (s20.hi & 0x00ffffff) | 0x48000000)) === -1);
expect("stubNumber rejects non-stub bytes", stubNumber(new I64(0, 0)) === -1);

const seeded = kernelImage([[0x200, 20], [0x210, 24]]);
const rSeed = discoverStubs(seeded, baseTable({ k_stubs: { 20: 0x200, 24: 0x210 } }), seeded.at(0), [20, 24]);
expect("seeds satisfy the want list", rSeed.ok && rSeed.seeded === 2 && rSeed.reads === 0,
  rSeed.text);

const mislabelled = kernelImage([[0x220, 21], [0x400, 20]]);
const rBadSeed = discoverStubs(mislabelled, baseTable({ k_stubs: { 20: 0x220 } }), mislabelled.at(0), [20]);
expect("a seed whose imm disagrees is rejected",
  rBadSeed.badSeeds.length === 1 && rBadSeed.badSeeds[0].seen === 21,
  JSON.stringify(rBadSeed.badSeeds));
expect("the rejected syscall is still found by scanning",
  rBadSeed.ok && rBadSeed.found.get(20).low === mislabelled.at(0x400).low,
  rBadSeed.text);

const inWindow = kernelImage([[0x300, 5], [0x310, 6], [0x320, 54]]);
const rStage1 = discoverStubs(inWindow, baseTable(), inWindow.at(0), [5, 6, 54]);
expect("stage1 finds stubs inside the declared window",
  rStage1.ok && rStage1.scanned === 3 && rStage1.fallbackScanned === 0, rStage1.text);

// The 14.00 case: the table says 0x40000, the stubs live past it.
const pastWindow = kernelImage([[0x300, 20], [0x50000, 663]]);
const rFallback = discoverStubs(pastWindow, baseTable(), pastWindow.at(0), [20, 663]);
expect("fallback finds a stub past k_scan_stage1",
  rFallback.ok && rFallback.fallbackScanned === 1 && rFallback.stopped === null,
  rFallback.text);
expect("fallback is reported as used, with the declared bound",
  rFallback.fallbackUsed === true && rFallback.declaredStage1 === 0x40000,
  JSON.stringify({ used: rFallback.fallbackUsed, declared: rFallback.declaredStage1 }));

const rNoFallback = discoverStubs(pastWindow, baseTable(), pastWindow.at(0), [20, 663], { fallback: false });
expect("with the fallback off the stub stays missing, and the report says so",
  rNoFallback.ok === false && rNoFallback.missing.join(",") === "663" && rNoFallback.stopped === null,
  rNoFallback.text);

const rBudget = discoverStubs(pastWindow, baseTable(), pastWindow.at(0), [663], { maxReads: 4 });
expect("the read budget stops the scan instead of hanging",
  rBudget.ok === false && rBudget.stopped && rBudget.stopped.reason === "read-budget",
  rBudget.text);

const short = kernelImage([[0x800, 20]], 0x1000);
const rFault = discoverStubs(short, baseTable(), short.at(0), [20, 999]);
expect("a read past the mapping stops the scan and does not throw",
  rFault.ok === false && rFault.stopped && rFault.stopped.reason === "read-fault",
  rFault.text);

// ------------------------------------------------------------------ caller

const callImg = makeImage(0x3000);
const callMem = mem(callImg);
for (const entry of gadgetTable(off)) {
  const pat = entry[2];
  const rva = off[entry[1]];
  for (let i = 0; i < pat.length; i++)
    if (pat[i] !== null) callMem.write1(callMem.at(rva + i), pat[i]);
}
const callGate = verifyGadgets(callMem, off, callMem.at(0));

const cell = callMem.leakval(Math.expm1);
callMem.write8(cell.add32(0x18), callMem.at(0x2000)); // fake JSCell
callMem.write8(callMem.at(0x2028), callMem.at(0x2400)); // its m_function slot

const calls = buildCaller({
  p: callMem,
  off: off,
  int64: I64,
  gadgets: callGate.addr,
  stubs: new Map([[20, callMem.at(0x300)]]),
  cell: cell,
});

expect("caller arms the expm1 slot", calls.isArmed() === true &&
  callMem.read8(calls.mainMf).low === callGate.addr.G0.low &&
  callMem.read8(calls.mainMf).hi === callGate.addr.G0.hi);

// -- layout: the frame the ROP entry walks
const c = calls.ctx;
const target = callMem.at(0x310);
calls.layout(c, target, [0x11, 0x22]);

const u32 = new Uint32Array(c.stackDv.buffer);
let idx = -1;
for (let i = 0; i < u32.length; i++)
  if (u32[i] === target.low) {
    idx = i;
    break;
  }

expect("the target lands in the frame", idx >= 0);
expect("the frame is 8-byte slot aligned", idx % 2 === 0, "u32 index " + idx);
expect("args sit in register order",
  idx >= 4 && u32[idx - 2] === 0x22 && u32[idx - 4] === callGate.addr.POP_RSI_RET.low,
  [u32[idx - 4], u32[idx - 2]].join(","));
expect("the epilogue follows the target",
  u32[idx + 2] === callGate.addr.POP_RDI_RET.low &&
  u32[idx + 4] === c.F.low &&
  u32[idx + 6] === callGate.addr.MOV_RDI_RAX_RET.low &&
  u32[idx + 8] === callGate.addr.POP_RAX_RET.low &&
  u32[idx + 10] === 0x0a &&
  u32[idx + 12] === callGate.addr.LEAVE_RET.low,
  [u32[idx + 2], u32[idx + 4], u32[idx + 6], u32[idx + 10]].map((x) => x.toString(16)).join(","));
expect("the ret slot is 16-byte aligned at the call",
  ((c.K.low + idx * 4) & 0xf) === 0,
  "0x" + ((c.K.low + idx * 4) >>> 0).toString(16));

// G5 is "push rdx; pop rsp; ret", so the pivot value must be the frame base --
// the ret then pops insts[0] and leaves rsp on arg0 -- and the call target must
// sit exactly two slots past it per stacked argument.
const TARGET_IDX = 4; // pop rdi, arg0, pop rsi, arg1
const pivotSlot = c.pivotDv.getUint32(off.pivot_view_sp, true);
const pivotHi = c.pivotDv.getUint32(off.pivot_view_sp + 4, true);
const pivotOff = (pivotSlot - c.K.low) >>> 0;
expect("the pivot points at the frame base",
  pivotHi === c.K.hi &&
    pivotOff === idx * 4 - 8 * TARGET_IDX &&
    u32[pivotOff / 4] === callGate.addr.POP_RDI_RET.low,
  "0x" + pivotSlot.toString(16) + " frame=" + pivotOff);

// -- the borrow is returned
const sentinel = callMem.at(0x1234);
callMem.write8(calls.pivotCell, sentinel);
calls.sc(20);
const after = callMem.read8(calls.pivotCell);
expect("sc() restores the pivot cell after the call",
  after.low === sentinel.low && after.hi === sentinel.hi,
  "0x" + after.low.toString(16));

let threw = "";
try {
  calls.sc(9999);
} catch (e) {
  threw = e.message;
}
expect("an unknown syscall refuses instead of jumping to undefined",
  /no verified stub/.test(threw), threw);

calls.disarm();
const restored = callMem.read8(calls.mainMf);
expect("disarm puts the original m_function back",
  calls.isArmed() === false &&
    restored.low === callMem.at(0x2400).low &&
    restored.hi === callMem.at(0x2400).hi,
  "0x" + restored.low.toString(16));

// -- addresses and errno
const ab1 = new ArrayBuffer(0x40);
const ab2 = new ArrayBuffer(0x40);
const a1 = calls.bufAddr(ab1);
const a2 = calls.bufAddr(ab2);
const walk = callMem.read8(callMem.leakval(ab1).add32(0x10));
const data = callMem.read8(walk.add32(0x10));
expect("bufAddr walks cell -> impl -> data",
  a1.low === data.low && a1.hi === data.hi, "0x" + a1.low.toString(16));
expect("two buffers do not share an address", a1.low !== a2.low);

callMem.write4(callMem.at(0x500), 22);
const errPtr = callMem.at(0x500);
expect("errno reads the int behind the pointer", errnoAt(callMem, errPtr.low, errPtr.hi, I64) === 22);
expect("errno reports -1 for a null pointer", errnoAt(callMem, 0, 0, I64) === -1);

// -- refusals
let msg = "";
try {
  buildCaller({
    p: callMem,
    off: off,
    int64: I64,
    gadgets: Object.assign({}, callGate.addr, { G5: undefined }),
    stubs: new Map(),
    cell: cell,
  });
} catch (e) {
  msg = e.message;
}
expect("a short gadget map is refused by name", /G5/.test(msg), msg);

let msg2 = "";
try {
  buildCaller({ p: callMem, off: off, gadgets: callGate.addr, cell: cell });
} catch (e) {
  msg2 = e.message;
}
expect("no stub map is refused", /stub map/.test(msg2), msg2);

console.log(fails === 0 ? "\nALL CHECKS PASSED" : "\n" + fails + " CHECK(S) FAILED");
process.exit(fails === 0 ? 0 : 1);
