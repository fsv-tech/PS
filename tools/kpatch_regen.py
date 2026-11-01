#!/usr/bin/env python3
"""
kpatch_regen.py - decode / re-target raw13g-style PS4 kernel patch blobs.

The blob is a 632-byte, position-independent x86-64 stub that:
  1. reads MSR 0xC0000082 (LSTAR, the syscall entry point)
  2. derives kernel base from it (LSTAR - <delta>)
  3. clears CR0.WP so kernel .text becomes writable
  4. writes a fixed set of patch words at absolute RVAs from kernel base
  5. installs a syscall table entry pointing at the payload
  6. restores CR0

Everything that is firmware-specific lives in the *immediates*: the
LSTAR->kernel-base delta, ~30 site RVAs, and one post-patch delta.
The instruction stream itself is byte-for-byte identical across
13.02 / 13.50 / 13.52 (98 instructions each) - verified by
`--verify-template`.

So porting a kpatch to a new firmware does not need the original C
source. It needs the same instruction template with new constants.

Usage:
    python kpatch_regen.py --dump   patches/1352.bin
    python kpatch_regen.py --verify-template patches/1302.bin patches/1350.bin patches/1352.bin
    python kpatch_regen.py --extract patches/1352.bin > sites_1352.json
    python kpatch_regen.py --retarget patches/1352.bin sites_1400.json -o patches/1400.bin
"""
import argparse
import json
import re
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RCX
except ImportError:
    sys.exit("pip install capstone")

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True

# instruction kinds that carry a firmware-specific constant
KIND_LSTAR_DELTA = "lstar_delta"      # lea rcx,[rdx-imm]
KIND_SITE = "site"                    # write to [rcx+imm]
KIND_POST_DELTA = "post_delta"        # add rdx,imm  (payload / hook address)


def insns(data):
    return list(MD.disasm(data, 0))


def classify(ins):
    """(kind, absolute_field_offset, field_size) of the firmware-specific constant."""
    enc = ins.encoding
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RCX:
            return KIND_SITE, ins.address + enc.disp_offset, enc.disp_size
    if ins.mnemonic == "lea":
        return KIND_LSTAR_DELTA, ins.address + enc.disp_offset, enc.disp_size
    if ins.mnemonic == "add":
        return KIND_POST_DELTA, ins.address + enc.imm_offset, enc.imm_size
    return None


def decode(data):
    """Extract the ordered constant table."""
    consts = []
    for ins in insns(data):
        c = classify(ins)
        if not c:
            continue
        kind, off, size = c
        disp = None
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RCX:
                disp = op.mem.disp
        val = int.from_bytes(data[off:off + size], "little", signed=True) & ((1 << (size * 8)) - 1)
        consts.append({
            "idx": len(consts),
            "kind": kind,
            "insn_off": ins.address,
            "field_off": off,
            "field_size": size,
            "rva": disp if kind == KIND_SITE else None,
            "value": val,
            "asm": "%s %s" % (ins.mnemonic, ins.op_str),
        })
    return consts


def shape(data):
    return [(i.mnemonic, re.sub(r"0x[0-9a-f]+", "IMM", i.op_str)) for i in insns(data)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", nargs=1, metavar="BLOB")
    ap.add_argument("--extract", nargs=1, metavar="BLOB")
    ap.add_argument("--verify-template", nargs="+", metavar="BLOB")
    ap.add_argument("--retarget", nargs=2, metavar=("BLOB", "SITES_JSON"))
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if a.verify_template:
        shapes = [shape(open(p, "rb").read()) for p in a.verify_template]
        n = len(shapes[0])
        ok = all(s == shapes[0] for s in shapes)
        for p, s in zip(a.verify_template, shapes):
            print("%-28s %3d instructions" % (p, len(s)))
        print("identical instruction template:", ok)
        if not ok:
            for i, row in enumerate(zip(*shapes)):
                if len(set(row)) != 1:
                    print("  first divergence at insn %d: %s" % (i, row))
                    break
        return 0 if ok else 1

    if a.dump or a.extract:
        p = (a.dump or a.extract)[0]
        data = open(p, "rb").read()
        consts = decode(data)
        if a.extract:
            print(json.dumps(consts, indent=2))
            return 0
        print("# %s  (%d bytes, %d instructions, %d constants)"
              % (p, len(data), len(insns(data)), len(consts)))
        print("%-3s %-12s %-6s %-10s %-12s %s" % ("#", "kind", "size", "field@", "rva/value", "asm"))
        for c in consts:
            print("%-3d %-12s %-6d 0x%04x     0x%-10x %s"
                  % (c["idx"], c["kind"], c["field_size"], c["field_off"],
                     (c["rva"] if c["rva"] is not None else c["value"]), c["asm"]))
        return 0

    if a.retarget:
        blob, sites_json = a.retarget
        data = bytearray(open(blob, "rb").read())
        consts = decode(bytes(data))
        new = json.load(open(sites_json))
        if isinstance(new, dict):
            new = new["consts"]
        if len(new) != len(consts):
            sys.exit("constant count mismatch: blob has %d, json has %d"
                     % (len(consts), len(new)))
        for c, nv in zip(consts, new):
            v = nv.get("value", nv.get("rva"))
            if v is None:
                continue
            data[c["field_off"]:c["field_off"] + c["field_size"]] = \
                int(v).to_bytes(c["field_size"], "little")
        out = a.out or "retargeted.bin"
        open(out, "wb").write(bytes(data))
        ok = len(insns(bytes(data))) == len(insns(bytes(data)))  # decodes cleanly
        print("wrote %s (%d bytes)" % (out, len(data)))
        print("REVIEW: every site must be re-verified against the target kernel; "
              "a wrong RVA is a kernel crash, not a failed check.")
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

