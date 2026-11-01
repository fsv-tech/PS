// Exercises boot.js's parts that can be tested without a console: UA parsing,
// table resolution across both host shapes, the anchor arithmetic, the decision
// rule, and -- with the fixture chain -- that a wrong module base is caught at
// the bases stage instead of becoming a scan from address zero.
import { boot, basesFrom, decide, resolveEntry, fwKeyFromUA } from "../boot.js";
import { looksAligned } from "../fcall.js";
import { makeImage, mem, I64 } from "./mock-memory.mjs";

let fails = 0;
function expect(name, cond, detail) {
  if (cond) console.log("ok   " + name);
  else {
    fails++;
    console.log("FAIL " + name + (detail ? "  -> " + detail : ""));
  }
}

// ------------------------------------------------------------------ firmware

const ua1400 = "Mozilla/5.0 (PlayStation 4/14.00) AppleWebKit/605.1.15";
const ua1352 = "Mozilla/5.0 (PlayStation 4/13.52) AppleWebKit/605.1.15";

expect("14.00 UA -> 14.00", fwKeyFromUA(ua1400) === "14.00", fwKeyFromUA(ua1400));
expect("13.52 UA -> 13.52", fwKeyFromUA(ua1352) === "13.52", fwKeyFromUA(ua1352));
expect("non-PS4 UA -> null", fwKeyFromUA("Mozilla/5.0 (Windows NT 10.0)") === null);

const fork = {
  offsetsFor: function (ua) {
    const k = fwKeyFromUA(ua);
    return { key: k, off: k === "14.00" ? { wk_expm1_builtin: 1 } : null };
  },
};
const host = { PS4: { "14.00": { wk_expm1_builtin: 2 }, "13.52": { wk_expm1_builtin: 3 } } };

expect("ps4_offsets.js shape resolves", resolveEntry(fork, ua1400).off.wk_expm1_builtin === 1);
expect("fwtable.js shape resolves", resolveEntry(host, ua1400).off.wk_expm1_builtin === 2);
expect("an unknown firmware reports why",
  resolveEntry({}, ua1400).why === "no table entry for 14.00" &&
    resolveEntry(host, "nonsense").why === "not a PlayStation 4 UA",
  JSON.stringify([resolveEntry({}, ua1400).why, resolveEntry(host, "nonsense").why]));
expect("a forced key bypasses UA parsing",
  resolveEntry(host, ua1400, "13.52").off.wk_expm1_builtin === 3,
  JSON.stringify(resolveEntry(host, ua1400, "13.52")));

// ------------------------------------------------------------------ bases

expect("an aligned module base passes", looksAligned(new I64(0x10000000, 8)) === true);
expect("a 0x800-unaligned base fails", looksAligned(new I64(0x10000800, 8)) === false);
expect("a base under 4 GB fails", looksAligned(new I64(0x10000000, 0)) === false);

const off = {
  wk_expm1_builtin: 0x198000,
  wk_JSFunction_m_function: 0x28,
  wk___imp___error: 0x1000,
  k__error: 0x4000,
};

const img = makeImage(0x30000);
const m = mem(img);
const cell = m.leakval(Math.expm1);
m.write8(cell.add32(0x18), m.at(0x2000)); // JSCell
m.write8(m.at(0x2028), new I64(0x10198000, 8)); // native function = webkit + 0x198000
m.write8(m.at(0x1000), new I64(0x10024000, 8)); // __error slot = libkernel + 0x4000

const b = basesFrom(m, off);
expect("webkit base comes out of the expm1 anchor",
  b.webkitBase.low === 0x10000000 && b.webkitBase.hi === 8,
  "0x" + b.webkitBase.toString(16));
expect("libkernel base comes out of the __error anchor",
  b.libkernelBase.low === 0x10020000 && b.libkernelBase.hi === 8,
  "0x" + b.libkernelBase.toString(16));
expect("both anchors pass the alignment gate", b.ok === true, b.text);

const offBad = Object.assign({}, off, { wk_expm1_builtin: 0x198008 });
const bBad = basesFrom(m, offBad);
expect("a wrong anchor is caught, and the text says so",
  bBad.ok === false && /NOT 0x4000-aligned/.test(bBad.text), bBad.text);

// ------------------------------------------------------------------ decision

function results(pairs) {
  return Object.keys(pairs).map(function (k) {
    return { name: k, verdict: pairs[k], detail: "" };
  });
}

const cases = [
  ["SLEEPS wins over everything", { "AIO-WAIT": "SLEEPS", "AIO-DELETE": "CLOSED" }, "lapse"],
  ["gate + live delete -> TOCTOU", { "AIO-WAIT": "GATED", "AIO-DELETE": "ALIVE" }, "delete-toctou"],
  ["gate + dead delete -> dipsw", { "AIO-WAIT": "GATED", "AIO-DELETE": "CLOSED" }, "dipsw"],
  ["ambiguous asks for a re-run", { "AIO-WAIT": "AMBIGUOUS", "AIO-DELETE": "ALIVE" }, "ambiguous"],
  ["submit refused", { "AIO-WAIT": "CLOSED", "AIO-DELETE": "CLOSED" }, "submit-closed"],
  ["nothing ran", {}, "inconclusive"],
];

for (const c of cases) {
  const d = decide(results(c[1]));
  expect(c[0], d.code === c[2], d.code);
}
expect("the decision carries the numbers it decided on",
  /aio wait=GATED delete=ALIVE/.test(decide(results({ "AIO-WAIT": "GATED", "AIO-DELETE": "ALIVE" })).body));

// ------------------------------------------------------------------ stages

const missing = await boot({ base: "./no-such-chain/" });
expect("a missing chain fails at the import stage",
  missing.ok === false && missing.stage === "import",
  missing.stage + " / " + missing.error);

const fake = await boot({ base: "./tools/fixtures/chain/", fw: "14.00" });
expect("the fixture chain reaches the primitive", fake.log.some((l) => l.t === "PRIMITIVE"));
expect("a zero memory primitive is refused at the bases stage",
  fake.ok === false && fake.stage === "bases",
  fake.stage + " / " + fake.error);
expect("the refusal happens before the gadget gate",
  fake.gate === null && !fake.log.some((l) => l.t === "GADGETS"));

delete globalThis.p;

console.log(fails === 0 ? "\nALL CHECKS PASSED" : "\n" + fails + " CHECK(S) FAILED");
process.exit(fails === 0 ? 0 : 1);


