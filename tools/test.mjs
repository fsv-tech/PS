// Proves three things:
//   1. the gate refuses an unmeasured 14.00 table and rejects zeroed /
//      out-of-range / half-filled / complete-but-unmeasured entries;
//   2. the ES5 gate inlined in index.html and measure.html behaves exactly like
//      gate.js + fwtable.js -- the console build cannot silently drift;
//   3. both HTML pages are strict ES5, because the PS4 system browser will not
//      run a module script, an arrow function or a URLSearchParams constructor.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PS4, REQUIRED_KEYS, OPTIONAL_KEYS } from "../fwtable.js";
import { checkEntry, detectFirmware } from "../gate.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

let fails = 0;
function check(name, cond, extra) {
  if (cond) {
    console.log("ok   " + name);
  } else {
    fails++;
    console.log("FAIL " + name + (extra ? "  -> " + extra : ""));
  }
}

// ---------------------------------------------------------------- 1. the gate

const ua1400 = "Mozilla/5.0 (PlayStation 4 14.00) AppleWebKit/537.73 (KHTML, like Gecko)";
const ua1400s = "Mozilla/5.0 (PlayStation 4/14.00) AppleWebKit/537.36 (KHTML, like Gecko)";
const ua1352 = "Mozilla/5.0 (PlayStation 4/13.52) AppleWebKit/537.73 (KHTML, like Gecko)";

check("14.00 UA (space form) -> key 14.00", detectFirmware(ua1400).key === "14.00", detectFirmware(ua1400).key);
check("14.00 UA (slash form) -> key 14.00", detectFirmware(ua1400s).key === "14.00", detectFirmware(ua1400s).key);
check("14.00 UA -> fwnum 1400", detectFirmware(ua1400).fwnum === "1400", detectFirmware(ua1400).fwnum);
check("13.52 UA -> key 13.52", detectFirmware(ua1352).key === "13.52", detectFirmware(ua1352).key);
check("non-PS4 UA -> null", detectFirmware("Mozilla/5.0 (Windows NT 10.0)").key === null);

const shipped = checkEntry(PS4["14.00"], REQUIRED_KEYS);
check("shipped 14.00 refuses", shipped.ok === false, JSON.stringify(shipped.state));
check("shipped 14.00 is 'unmeasured'", shipped.state === "unmeasured", shipped.state);
check("shipped 14.00 lists every offset key",
  shipped.missing.length === REQUIRED_KEYS.length - 1,
  shipped.missing.length + " of " + (REQUIRED_KEYS.length - 1));

// A complete table must pass (values are synthetic: this only tests the gate).
const full = { measured: true, fw_status: "state=TEST" };
for (const k of REQUIRED_KEYS) {
  if (k === "fw_status") continue;
  full[k] = k.endsWith("_m_function") || k.endsWith("m_impl") || k.endsWith("m_data")
    ? 0x28
    : 0x1000 + REQUIRED_KEYS.indexOf(k);
}
const good = checkEntry(full, REQUIRED_KEYS);
check("complete table passes", good.ok === true, JSON.stringify(good));

const zeroed = Object.assign({}, full, { k_jmp_rsi: 0 });
const z = checkEntry(zeroed, REQUIRED_KEYS);
check("zero RVA rejected", z.ok === false && z.state === "invalid", JSON.stringify(z.bad));

const wild = Object.assign({}, full, { k_evf_cv: 0x1_0000_0000 });
const w = checkEntry(wild, REQUIRED_KEYS);
check("out-of-range RVA rejected", w.ok === false && w.state === "invalid", JSON.stringify(w.bad));

const half = Object.assign({}, full, { measured: true });
delete half.wk_POP_RAX_RET;
const h = checkEntry(half, REQUIRED_KEYS);
check("half-filled table blocked", h.ok === false && h.state === "incomplete", h.state);

// The hole that used to exist: a table pasted in from someone else's numbers,
// every key present, measured:false -- the old gate returned ok:true.
const borrowed = Object.assign({}, full, { measured: false });
const b = checkEntry(borrowed, REQUIRED_KEYS);
check("complete but measured:false refused", b.ok === false, JSON.stringify(b));
check("complete but measured:false reports 'unmeasured'", b.state === "unmeasured", b.state);

const noFlag = Object.assign({}, full);
delete noFlag.measured;
const nf = checkEntry(noFlag, REQUIRED_KEYS);
check("complete without measured:true refused", nf.ok === false, JSON.stringify(nf.state));

// ------------------------------------------------- 2. inline gate parity

const BEGIN = "/* GATE-INLINE-BEGIN";
const END = "/* GATE-INLINE-END */";

function loadInline(file) {
  const html = readFileSync(join(root, file), "utf8");
  const a = html.indexOf(BEGIN);
  const b = html.indexOf(END);
  if (a < 0 || b < 0) throw new Error(file + ": gate markers missing");
  const code = html.slice(a, b);
  const factory = new Function(
    "var window={},document={getElementById:function(){return null;}};\n" +
    code +
    "\nreturn {REQUIRED_KEYS:REQUIRED_KEYS, PS4:PS4, checkEntry:checkEntry, detectFirmware:detectFirmware};"
  );
  return factory();
}

function sameVerdict(x, y) {
  return JSON.stringify(x) === JSON.stringify(y);
}

for (const file of ["index.html", "measure.html"]) {
  let inline;
  try {
    inline = loadInline(file);
  } catch (e) {
    fails++;
    console.log("FAIL " + file + " inline gate loads  -> " + e.message);
    continue;
  }
  check(file + ": inline REQUIRED_KEYS == fwtable.js",
    JSON.stringify(inline.REQUIRED_KEYS) === JSON.stringify(REQUIRED_KEYS));
  check(file + ": inline PS4 table == fwtable.js",
    JSON.stringify(inline.PS4) === JSON.stringify({ "14.00": PS4["14.00"] }));

  const fixtures = [
    ["none", null],
    ["shipped", PS4["14.00"]],
    ["full", full],
    ["borrowed", borrowed],
    ["zeroed", zeroed],
    ["wild", wild],
    ["half", half],
  ];
  let allMatch = true, detail = "";
  for (const [name, entry] of fixtures) {
    const a = inline.checkEntry(entry, REQUIRED_KEYS);
    const bVerdict = checkEntry(entry, REQUIRED_KEYS);
    if (!sameVerdict(a, bVerdict)) {
      allMatch = false;
      detail = name + ": inline " + JSON.stringify(a) + " vs module " + JSON.stringify(bVerdict);
      break;
    }
  }
  check(file + ": gate verdicts match gate.js on " + fixtures.length + " fixtures",
    allMatch, detail);

  let uaMatch = true;
  for (const ua of [ua1400, ua1400s, ua1352, "", "Mozilla/5.0 (X11; Linux x86_64)"]) {
    if (!sameVerdict(inline.detectFirmware(ua), detectFirmware(ua))) { uaMatch = false; break; }
  }
  check(file + ": UA parsing matches gate.js", uaMatch);
}

// ------------------------------------------------------ 3. strict ES5 lint

// Anything here fails to parse on a 537.x WebKit, which is what the PS4 browser
// is -- and a page that does not parse shows the console nothing at all.
const ES6 = [
  ["module script", /type\s*=\s*["']module["']/],
  ["import statement", /\bimport\s+[\w{*"']/],
  ["export statement", /\bexport\s+[\w{*]/],
  ["arrow function", /=>/],
  ["block-scoped binding", /\b(?:const|let)\s+[A-Za-z_$]/],
  ["template literal", /`/],
  ["URLSearchParams", /URLSearchParams/],
  ["async/await", /\basync\s+function|\bawait\s+/],
  ["optional chaining", /\?\./],
  // A *call* is the violation; `typeof Object.assign === "function"` is how the
  // capability probe asks whether the method exists, which is safe ES5.
  ["Object.assign call", /Object\.assign\s*\(/],
  ["Number.isFinite call", /Number\.isFinite\s*\(/],
  ["for...of", /for\s*\(\s*(?:var|let|const)\s+\w+\s+of\s/],
];

// Blank out comments and string literals so prose in a comment (or the word
// "import" inside a KEY_SOURCE label) is not mistaken for a syntax error. A
// construct that only exists inside a string cannot break the engine.
function stripNonCode(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "*") {
      const e = src.indexOf("*/", i + 2);
      i = e < 0 ? n : e + 2;
      out += " ";
      continue;
    }
    if (c === "/" && d === "/") {
      const e = src.indexOf("\n", i);
      i = e < 0 ? n : e;
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c;
      i++;
      while (i < n && src[i] !== q) {
        if (src[i] === "\\") i++;
        i++;
      }
      i++;
      out += '""';
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

for (const file of ["index.html", "measure.html", "caps.html"]) {
  const html = readFileSync(join(root, file), "utf8");
  // HTML comments and the <style> block are not JavaScript at all.
  const shell = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "");
  // The module-script check has to see the raw tag; the rest runs on code only.
  const rawHits = ES6.filter(([name, re]) => name === "module script" && re.test(shell));
  const js = stripNonCode(shell);
  const codeHits = ES6.filter(([name, re]) => name !== "module script" && re.test(js));
  const hits = rawHits.concat(codeHits).map(([name]) => name);
  check(file + ": strict ES5 (" + ES6.length + " constructs)", hits.length === 0, hits.join(", "));
}

// Sanity: the lint must actually catch something.
check("ES5 lint is not a no-op", ES6.some(([, re]) => re.test("var f = () => 1;")));

console.log(fails === 0 ? "\nALL CHECKS PASSED" : "\n" + fails + " CHECK(S) FAILED");
process.exit(fails === 0 ? 0 : 1);
