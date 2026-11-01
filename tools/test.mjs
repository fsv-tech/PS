// Proves the gate does what the UI claims: refuses an unmeasured 14.00 table,
// accepts a complete one, and rejects zeroed or out-of-range values.
import { PS4, REQUIRED_KEYS } from "../fwtable.js";
import { checkEntry, detectFirmware } from "../gate.js";

let fails = 0;
function check(name, cond, extra) {
  if (cond) {
    console.log("ok   " + name);
  } else {
    fails++;
    console.log("FAIL " + name + (extra ? "  -> " + extra : ""));
  }
}

// 1. UA parsing, including the hex minor quirk.
const ua1400 = "Mozilla/5.0 (PlayStation 4/14.00) AppleWebKit/605.1.15";
const ua1352 = "Mozilla/5.0 (PlayStation 4/13.52) AppleWebKit/605.1.15";
check("14.00 UA -> key 14.00", detectFirmware(ua1400).key === "14.00", detectFirmware(ua1400).key);
check("14.00 UA -> fwnum 1400", detectFirmware(ua1400).fwnum === "1400", detectFirmware(ua1400).fwnum);
check("13.52 UA -> key 13.52", detectFirmware(ua1352).key === "13.52", detectFirmware(ua1352).key);
check("non-PS4 UA -> null", detectFirmware("Mozilla/5.0 (Windows NT 10.0)").key === null);

// 2. The shipped 14.00 entry must not pass.
const shipped = checkEntry(PS4["14.00"], REQUIRED_KEYS);
check("shipped 14.00 refuses", shipped.ok === false, JSON.stringify(shipped.state));
check("shipped 14.00 is 'unmeasured'", shipped.state === "unmeasured", shipped.state);
check("shipped 14.00 lists every offset key",
  shipped.missing.length === REQUIRED_KEYS.length - 1,
  shipped.missing.length + " of " + (REQUIRED_KEYS.length - 1));

// 3. A complete table must pass (values are synthetic: this only tests the gate).
const full = { measured: true, fw_status: "state=TEST" };
for (const k of REQUIRED_KEYS) {
  if (k === "fw_status") continue;
  full[k] = k.endsWith("_m_function") || k.endsWith("m_impl") || k.endsWith("m_data") ? 0x28 : 0x1000 + REQUIRED_KEYS.indexOf(k);
}
const good = checkEntry(full, REQUIRED_KEYS);
check("complete table passes", good.ok === true, JSON.stringify(good));

// 4. Zeroed value is caught, not accepted as 0.
const zeroed = Object.assign({}, full, { k_jmp_rsi: 0 });
const z = checkEntry(zeroed, REQUIRED_KEYS);
check("zero RVA rejected", z.ok === false && z.state === "invalid", JSON.stringify(z.bad));

// 5. Out-of-range value is caught.
const wild = Object.assign({}, full, { k_evf_cv: 0x1_0000_0000 });
const w = checkEntry(wild, REQUIRED_KEYS);
check("out-of-range RVA rejected", w.ok === false && w.state === "invalid", JSON.stringify(w.bad));

// 6. Half-filled table reports 'incomplete', not 'ready'.
const half = Object.assign({}, full, { measured: true });
delete half.wk_POP_RAX_RET;
const h = checkEntry(half, REQUIRED_KEYS);
check("half-filled table blocked", h.ok === false && h.state === "incomplete", h.state);

console.log(fails === 0 ? "\nALL CHECKS PASSED" : "\n" + fails + " CHECK(S) FAILED");
process.exit(fails === 0 ? 0 : 1);
