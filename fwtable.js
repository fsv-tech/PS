// fwtable.js -- per-firmware offset table, schema-compatible with raw13g's
// ps4_offsets.js (same REQUIRED_KEYS / OPTIONAL_KEYS contract) so a table
// measured for 14.00 can be dropped in without touching the host.
//
// NOTHING IN THIS FILE IS MEASURED YET. Values are intentionally absent: a
// guessed RVA does not "fail loudly" on a console, it corrupts memory in a
// place the kernel will not survive. gate.js refuses to launch until every
// REQUIRED key below is present and in range.

export const REQUIRED_KEYS = [
  "fw_status",
  "wk_expm1_builtin",
  "wk_JSFunction_m_function",
  "wk_POP_RDI_RET",
  "wk_POP_RSI_RET",
  "wk_POP_RDX_RET",
  "wk_POP_RCX_RET",
  "wk_POP_RAX_RET",
  "wk_POP_R8_RET",
  "wk_POP_R9_RET",
  "wk_LEAVE_RET",
  "wk_MOV_QWORD_PTR_RDI_RAX_RET",
  "wk_MOV_RDI_RSI_30_CALL",
  "wk_POP_RAX_MOV_RAX_JMP_18",
  "wk_PUSH_RBP_MOV_RBP_RSP_10",
  "wk_MOV_RDI_RAX_8_CALL_20",
  "wk_MOV_RDX_RAX_18_CALL_10",
  "wk_PUSH_RDX_POP_RSP_RET",
  "pivot_view_sp",
  "wk_ArrayBuffer_m_impl",
  "wk_ArrayBuffer_m_contents_m_data",
  "wk___imp___error",
  "k__error",
  "k_scan_stage1",
  "k_scan_stage2",
  "k_evf_cv",
  "k_sysent_661",
  "k_jmp_rsi",
];

export const OPTIONAL_KEYS = [
  "k_stubs",
  "wk___imp_pthread_create",
  "k_pthread_create",
  "kpatch",
  "payload",
  "alias_of",
  "k_idt_rsvd",
];

// Which measurement each key comes from, so measure.html can tell you what to
// go and find. "wk_" = RVA inside the WebKit module; "k_" = RVA inside the
// kernel image (measured the same way raw13g measured 13.50/13.02: dump ->
// rebase against tier0 -> derive against tier1, then adversarial re-check).
export const KEY_SOURCE = {
  fw_status: "free text; the only key allowed to be a sentence",
  wk_expm1_builtin: "webkit module RVA",
  wk_JSFunction_m_function: "struct offset",
  wk_POP_RDI_RET: "webkit module RVA (ROP gadget)",
  wk_POP_RSI_RET: "webkit module RVA (ROP gadget)",
  wk_POP_RDX_RET: "webkit module RVA (ROP gadget)",
  wk_POP_RCX_RET: "webkit module RVA (ROP gadget)",
  wk_POP_RAX_RET: "webkit module RVA (ROP gadget)",
  wk_POP_R8_RET: "webkit module RVA (ROP gadget)",
  wk_POP_R9_RET: "webkit module RVA (ROP gadget)",
  wk_LEAVE_RET: "webkit module RVA (ROP gadget)",
  wk_MOV_QWORD_PTR_RDI_RAX_RET: "webkit module RVA (ROP gadget)",
  wk_MOV_RDI_RSI_30_CALL: "webkit module RVA (ROP gadget)",
  wk_POP_RAX_MOV_RAX_JMP_18: "webkit module RVA (ROP gadget)",
  wk_PUSH_RBP_MOV_RBP_RSP_10: "webkit module RVA (ROP gadget)",
  wk_MOV_RDI_RAX_8_CALL_20: "webkit module RVA (ROP gadget)",
  wk_MOV_RDX_RAX_18_CALL_10: "webkit module RVA (ROP gadget)",
  wk_PUSH_RDX_POP_RSP_RET: "webkit module RVA (ROP gadget / stack pivot)",
  pivot_view_sp: "stack pivot target RVA",
  wk_ArrayBuffer_m_impl: "struct offset",
  wk_ArrayBuffer_m_contents_m_data: "struct offset",
  wk___imp___error: "webkit import slot RVA",
  k__error: "kernel RVA (symbol behind __error)",
  k_scan_stage1: "kernel RVA",
  k_scan_stage2: "kernel RVA",
  k_evf_cv: "kernel RVA",
  k_sysent_661: "kernel RVA (sysent entry used for the kexec swap)",
  k_jmp_rsi: "kernel RVA",
  k_idt_rsvd: "kernel RVA (idt_rsvd anchor; .text shifts with it)",
  kpatch: "blob filename in patches/",
  payload: "blob filename in the package root",
  alias_of: "firmware key this one inherits from",
};

export const PS4 = {
  // Minor is the two hex digits the console reports in its UA, so 14.00 is
  // key "14.00" and fwnum 1400.
  "14.00": {
    measured: false,
    fw_status:
      "state=NO-TABLE no webkit module measured, no kernel_1400.elf, no 1400 kpatch blob " +
      "payload=none(kpatch+payload for 14.00 not built)",
    // Everything the host needs and does not have. Left explicitly empty
    // rather than zeroed, so a half-finished table can never pass the gate.
    missing: REQUIRED_KEYS.filter((k) => k !== "fw_status"),
  },
};

// The chain itself (jb.js) is not part of this package: it is the exploit, and
// no 14.00-capable one exists to ship. The host is deliberately separable from
// it so the front end can be finished and reviewed before the chain lands.
export function offsetsFor(fwkey) {
  return PS4[fwkey] || null;
}
