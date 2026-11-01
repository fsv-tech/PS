"""Repack the BD-J jar with the raw14g host at bonk/webkit/.

Reads the tree already extracted from hen.iso, keeps the original entry order
(META-INF first, as the BD-J loader expects), and writes a new jar.

This does NOT re-sign the jar: SIG-BD00.SF / SIG-BD00.RSA are copied verbatim
and no longer match the archive. Fine for a console that ignores BD-J JAR
signing, not fine for a retail disc.

    python tools/rebuild_jar.py [--src DIR] [--out FILE]
"""

import argparse
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.path.dirname(HERE)
SKIP = {"tools", "package.json"}


def ordered(names):
    """META-INF first, then everything else, each group sorted."""
    return sorted(names, key=lambda p: (0 if p.split("/")[0] == "META-INF" else 1, p))


def main():
    root = os.path.dirname(HOST)  # C:\...\Hen
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.path.join(root, "_extracted"),
                    help="tree extracted from hen.iso")
    ap.add_argument("--out", default=os.path.join(root, "hen-repacked.jar"))
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        sys.exit("source tree not found: " + args.src)

    originals = {}
    for base, _dirs, files in os.walk(args.src):
        for f in files:
            full = os.path.join(base, f)
            arc = os.path.relpath(full, args.src).replace(os.sep, "/")
            with open(full, "rb") as fh:
                originals[arc] = fh.read()

    staging = {}
    for name in sorted(os.listdir(HOST)):
        full = os.path.join(HOST, name)
        if name in SKIP or name.endswith(".md"):
            continue
        if os.path.isfile(full):
            with open(full, "rb") as fh:
                staging["bonk/webkit/" + name] = fh.read()

    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        for arc in ordered(list(originals)):
            z.writestr(arc, originals[arc])
        for arc in ordered(list(staging)):
            z.writestr(arc, staging[arc])

    print("wrote %s" % args.out)
    print("  %d original entries + %d host files" % (len(originals), len(staging)))
    for arc in sorted(staging):
        print("  + " + arc)
    print("  SIGNATURE: SIG-BD00.RSA copied unchanged -- archive is now unsigned")


if __name__ == "__main__":
    main()
