// Fixture table: the shape of a real entry, the numbers deliberately fake.
export const PS4 = {
  "14.00": {
    measured: false,
    fw_status: "state=FIXTURE not a real table",
    wk_expm1_builtin: 0x198000,
    wk_JSFunction_m_function: 0x28,
    wk___imp___error: 0x1000,
    k__error: 0x4000,
    k_scan_stage1: 0x40000,
    pivot_view_sp: 0x38,
    wk_ArrayBuffer_m_impl: 0x10,
    wk_ArrayBuffer_m_contents_m_data: 0x10,
  },
};

export function offsetsFor(uaString) {
  const m = (uaString || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
  if (!m) return { key: null, off: null };
  let minor = parseInt(m[2], 16).toString(16);
  if (minor.length < 2) minor = "0" + minor;
  const key = m[1] + "." + minor;
  return { key: key, off: PS4[key] || null };
}
