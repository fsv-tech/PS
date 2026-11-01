#!/usr/bin/env python3
"""Remove the hardcoded report-back host from a BD-J jar tree.

Two classes in this title carry a network endpoint baked into their constant
pool:

    org/bdj/Cfg.class    UTF8 "tester.f5rvoice.com"          (SERVER)
                         int  1992                            (PORT)
                         UTF8 "942a76d6946a34ce476bdabb09989f4c"  (CKEY)
    org/bdj/Boot.class   UTF8 "http://tester.f5rvoice.com:1992"
                         UTF8 "X-Ticket"

This script rewrites the two host strings in place to names under the
RFC 2606 reserved `.invalid` TLD, so the lookup fails locally instead of
resolving. Every replacement is byte-length identical, which keeps the class
file's constant-pool UTF8 lengths valid -- no recompilation, no reassembly of
the class structure, nothing else in the file moves.

    python tools/neutralize_beacon.py
    python tools/neutralize_beacon.py --src ../_extracted --out ../_extracted_neutered

What it does NOT do: fix the disc. Modifying any class invalidates
META-INF/SIG-BD00.SF|RSA, so the repacked jar is unsigned. That is exactly the
same state tools/rebuild_jar.py already puts you in.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import zipfile
from pathlib import Path

# old -> new, byte-for-byte equal length. `.invalid` is reserved (RFC 2606) and
# can never resolve, so the request fails in the resolver before any packet
# leaves the console.
PATCHES = {
    "org/bdj/Cfg.class": [
        (b"tester.f5rvoice.com", b"localhost.invalid.x"),
    ],
    "org/bdj/Boot.class": [
        (b"http://tester.f5rvoice.com:1992", b"http://localhost.invalid.x:1992"),
    ],
}

MARKERS = [b"f5rvoice", b"X-Ticket", b"942a76d6946a34ce476bdabb09989f4c"]
EXPECTED_HEN_SHA256 = "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06"


def find_all(haystack: bytes, needle: bytes) -> list[int]:
    out, start = [], 0
    while True:
        i = haystack.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def patch_file(path: Path, pairs) -> list[str]:
    raw = path.read_bytes()
    if raw[:4] != b"\xca\xfe\xba\xbe":
        raise SystemExit(f"{path}: not a class file (bad magic)")

    lines = []
    for old, new in pairs:
        if len(old) != len(new):
            raise SystemExit(f"length mismatch {old!r} -> {new!r} ({len(old)} != {len(new)})")
        offsets = find_all(raw, old)
        if not offsets:
            raise SystemExit(f"{path.name}: {old!r} not found -- already patched or wrong file")
        for off in offsets:
            raw = raw[:off] + new + raw[off + len(old):]
            lines.append(f"{path.name}: 0x{off:04x}  {old.decode()} -> {new.decode()}")
    path.write_bytes(raw)
    return lines


def verify(root: Path) -> tuple[list[str], list[str]]:
    """Return (problems, notes).

    Only the host is a defect. `X-Ticket` is a header name and the 32-hex CKEY
    is an application key -- neither is an address, both stay, and blanking them
    would only break the class file's own integrity for no gain.
    """
    problems: list[str] = []
    notes: list[str] = []
    hen = root / "bonk" / "hen.bin"
    if hen.is_file():
        digest = hashlib.sha256(hen.read_bytes()).hexdigest()
        if digest != EXPECTED_HEN_SHA256:
            problems.append(f"hen.bin sha256 changed: {digest}")
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix not in (".class", ".bin", ".MF", ".SF"):
            continue
        blob = f.read_bytes()
        rel = f.relative_to(root)
        if b"f5rvoice" in blob:
            problems.append(f"{rel}: still contains b'f5rvoice'")
        for m in (b"X-Ticket", b"942a76d6946a34ce476bdabb09989f4c"):
            if m in blob:
                notes.append(f"{rel}: keeps {m.decode()} (not an address)")
    return problems, notes


def main() -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(here.parent.parent / "_extracted"),
                    help="extracted jar tree (contains META-INF/ and org/bdj/)")
    ap.add_argument("--out", default=str(here.parent.parent / "_extracted_neutered"),
                    help="where to write the patched tree")
    ap.add_argument("--jar", default=str(here.parent.parent / "hen-neutered.jar"),
                    help="jar to write from the patched tree")
    ap.add_argument("--no-jar", action="store_true", help="tree only, skip the repack")
    args = ap.parse_args()

    src, out, jar = Path(args.src), Path(args.out), Path(args.jar)
    if not (src / "org" / "bdj" / "Cfg.class").is_file():
        raise SystemExit(f"{src}: no org/bdj/Cfg.class -- point --src at the extracted tree")

    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(src, out)

    lines = []
    for rel, pairs in PATCHES.items():
        lines += patch_file(out / rel, pairs)
    for line in lines:
        print("patched  " + line)

    problems, notes = verify(out)
    for n in notes:
        print("kept     " + n)
    if problems:
        for p in problems:
            print("PROBLEM  " + p, file=sys.stderr)
        return 1
    print("verified  no 'f5rvoice' left anywhere in the tree")
    print("verified  bonk/hen.bin sha256 unchanged")

    if not args.no_jar:
        # MANIFEST first, signature files next, then the payload tree -- the
        # layout the original image used.
        order = ["META-INF/MANIFEST.MF", "META-INF/SIG-BD00.SF", "META-INF/SIG-BD00.RSA"]
        names = [n for n in order if (out / n).is_file()]
        names += sorted(
            str(p.relative_to(out)).replace("\\", "/")
            for p in out.rglob("*")
            if p.is_file() and str(p.relative_to(out)).replace("\\", "/") not in order
        )
        with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as z:
            for n in names:
                z.write(out / n, n)
        size = jar.stat().st_size
        print(f"wrote     {jar}  ({size:,} bytes, {len(names)} entries)")
        print("WARNING   SIG-BD00.SF|RSA no longer match: this jar is unsigned.")
        print("          It only runs where BD-J signature checking is off.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
