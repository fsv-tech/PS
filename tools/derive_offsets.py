#!/usr/bin/env python3
"""
derive_offsets.py - carry a PS4 WebKit offset table to a new firmware.

raw13g's repo tells you to "derive its table with tools/kderive.py" but does
not publish that tool. This is a working replacement.

Method (differential, anchored):
  for every key in the reference table, take the bytes at the reference RVA,
  widen the window until the match is unique inside the reference module,
  then search the target module for that window. A hit gives the new RVA.

That works because these gadgets/anchors are short instruction windows inside
functions that rarely change between adjacent firmware builds - and when the
WebKit .sprx was not rebuilt at all (13.00 -> 13.50 -> 13.52 share every single
WebKit RVA) the table carries over untouched.

It does NOT tell you whether the JavaScriptCore bug still exists. Offsets are
addresses, not vulnerabilities.

Usage:
  python derive_offsets.py --selftest
  python derive_offsets.py --ref libSceWebKit2_1352.sprx --target libSceWebKit2_1400.sprx \
                           --table ps4_offsets_webkit_1352.json -o derived_1400.json
  python derive_offsets.py --ref ... --target ... --table ... --js   # emit JS block
"""
import argparse
import json
import struct
import sys

PT_LOAD = 1


def load_elf(path):
    """Return (data, segments[(vaddr, off, filesz)])."""
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        return data, [(0, 0, len(data))]
    if data[4] != 2:
        raise SystemExit("not ELF64: %s" % path)
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        if p_type != PT_LOAD:
            continue
        p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
        segs.append((p_vaddr, p_offset, p_filesz))
    segs.sort()
    return data, segs


def rva_slice(data, segs, rva, n):
    for vaddr, off, filesz in segs:
        if vaddr <= rva < vaddr + filesz:
            start = off + (rva - vaddr)
            return data[start:start + n]
    return None


def find_all(hay, needle):
    out, i = [], hay.find(needle)
    while i != -1:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def rva_of(segs, file_off):
    for vaddr, off, filesz in segs:
        if off <= file_off < off + filesz:
            return vaddr + (file_off - off)
    return None


def derive(ref_path, tgt_path, table):
    ref, ref_segs = load_elf(ref_path)
    tgt, tgt_segs = load_elf(tgt_path)
    results = {}
    for key, rva in table.items():
        if not isinstance(rva, int):
            continue
        rec = {"ref_rva": rva, "status": "no-window"}
        win = None
        for w in (8, 12, 16, 24, 32, 48, 64):
            blob = rva_slice(ref, ref_segs, rva, w)
            if blob is None or len(blob) < w:
                break
            if len(find_all(ref, blob)) == 1:
                win = blob
                break
        if win is None:
            blob = rva_slice(ref, ref_segs, rva, 64)
            if blob:
                win, rec["status"] = blob, "ambiguous-in-reference"
        if win:
            hits = find_all(tgt, win)
            rec["window"] = len(win)
            if len(hits) == 1:
                nr = rva_of(tgt_segs, hits[0])
                rec.update(status="ok", rva=nr, delta=(nr - rva) if nr is not None else None)
            elif not hits:
                rec["status"] = "MISSING-in-target"
            else:
                rec.update(status="ambiguous-in-target", hits=len(hits),
                           candidates=[rva_of(tgt_segs, h) for h in hits[:8]])
        results[key] = rec
    return results


def selftest():
    """Build two synthetic modules and check the deriver recovers the shift."""
    import os
    import tempfile

    def make(placements, size=0x4000):
        buf = bytearray(b"\x90" * size)
        for rva, blob in placements:
            buf[rva:rva + len(blob)] = blob
        return bytes(buf)

    g1 = bytes.fromhex("5f c3 48 89 f7 ff 56 30 90 90 90 90")
    g2 = bytes.fromhex("58 c3 41 5e 41 5f 48 8b 07 48 89 07 c9")
    g3 = bytes.fromhex("c9 c3 90 90 48 8d 05 aa bb cc dd")
    decoy = bytes.fromhex("5f c3")  # not enough on its own: must not be picked

    ref = make([(0x1000, g1), (0x2000, g2), (0x3000, g3), (0x0800, decoy), (0x0c00, decoy)])
    tgt = make([(0x1210, g1), (0x2450, g2), (0x3a80, g3), (0x0900, decoy), (0x0d00, decoy)])
    d = tempfile.mkdtemp()
    rp, tp = os.path.join(d, "ref.bin"), os.path.join(d, "tgt.bin")
    open(rp, "wb").write(ref)
    open(tp, "wb").write(tgt)

    table = {"g1": 0x1000, "g2": 0x2000, "g3": 0x3000}
    got = derive(rp, tp, table)
    expect = {"g1": 0x1210, "g2": 0x2450, "g3": 0x3a80}
    ok = True
    for k, want in expect.items():
        r = got[k]
        passed = r["status"] == "ok" and r["rva"] == want
        ok &= passed
        print("  %-4s ref=0x%04x -> %-6s rva=0x%04x (want 0x%04x) %s"
              % (k, table[k], r["status"], r.get("rva") or 0, want, "PASS" if passed else "FAIL"))

    # a key that does not exist in the target at all must be reported, not invented
    tgt2 = make([(0x1210, g1)])
    tp2 = os.path.join(d, "tgt2.bin")
    open(tp2, "wb").write(tgt2)
    got2 = derive(rp, tp2, {"g2": 0x2000})
    miss = got2["g2"]["status"] == "MISSING-in-target"
    ok &= miss
    print("  g2   absent in target -> %-17s %s" % (got2["g2"]["status"], "PASS" if miss else "FAIL"))
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--ref")
    ap.add_argument("--target")
    ap.add_argument("--table", help="JSON {key: ref_rva}")
    ap.add_argument("-o", "--out")
    ap.add_argument("--js", action="store_true", help="emit a ps4_offsets.js block")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not (a.ref and a.target and a.table):
        ap.print_help()
        return 2
    table = json.load(open(a.table))
    res = derive(a.ref, a.target, table)
    ok = sum(1 for v in res.values() if v["status"] == "ok")
    print("derived %d/%d keys" % (ok, len(res)))
    for k, v in res.items():
        if v["status"] != "ok":
            print("  ! %-32s %s" % (k, v["status"]))
    if a.js:
        lines = ["export const PS4_1400_WEBKIT_DERIVED = {"]
        for k, v in res.items():
            if v["status"] == "ok":
                lines.append('  %s: 0x%x,' % (k, v["rva"]))
            else:
                lines.append('  // %s: UNRESOLVED (%s)' % (k, v["status"]))
        lines.append("};")
        print("\n".join(lines))
    out = json.dumps(res, indent=2)
    if a.out:
        open(a.out, "w").write(out)
        print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
