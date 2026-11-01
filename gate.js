// gate.js -- decides whether the table entry for the detected firmware is
// complete enough to hand to the chain.
//
// The rule: no required key missing, no value out of range, no placeholder
// value. A firmware that fails here must not reach jb.html, because the chain
// has no second chance once it starts writing.

const RVA_LIMIT = 0x80000000; // above this it is not an RVA, it is a typo
const PLACEHOLDER = /^(0x0+|0+)$/;

function isEmpty(v) {
  return v === undefined || v === null || v === "";
}

// Returns { ok, missing[], bad[], state } where state is one of
// "ready" | "unmeasured" | "incomplete" | "invalid".
export function checkEntry(entry, requiredKeys) {
  if (!entry) {
    return { ok: false, state: "unmeasured", missing: requiredKeys.slice(), bad: [] };
  }
  const missing = [];
  const bad = [];

  for (const k of requiredKeys) {
    const v = entry[k];
    if (isEmpty(v)) {
      missing.push(k);
      continue;
    }
    if (typeof v === "number") {
      if (!Number.isFinite(v) || v < 0 || v >= RVA_LIMIT) {
        bad.push(k + ": out of range (" + v + ")");
      } else if (PLACEHOLDER.test("0x" + v.toString(16))) {
        bad.push(k + ": placeholder 0 -- never measured");
      }
    } else if (typeof v === "string") {
      if (!v.trim()) bad.push(k + ": empty string");
    } else {
      bad.push(k + ": unexpected type " + typeof v);
    }
  }

  if (bad.length) return { ok: false, state: "invalid", missing, bad };
  if (missing.length) {
    return {
      ok: false,
      // An entry that declares itself unmeasured is honest, not broken.
      state: entry.measured === false ? "unmeasured" : "incomplete",
      missing,
      bad,
    };
  }
  return { ok: true, state: "ready", missing, bad };
}

// PS4 UA carries the minor version as two hex digits: 13.52 -> 0x52, 14.00 -> 0x00.
export function detectFirmware(userAgent) {
  const m = /PlayStation\s+4[\/ ](\d+)\.(\d+)/.exec(userAgent || "");
  if (!m) return { key: null, fwnum: null };
  let minor = parseInt(m[2], 16).toString(16);
  if (minor.length < 2) minor = "0" + minor;
  const major = parseInt(m[1], 10);
  return { key: major + "." + minor, fwnum: String(major) + minor };
}
