#!/usr/bin/env python3
"""Convert QEMU ``screendump`` PPM files to PNG.

Usage:
    python tools/ppm2png.py in.ppm [out.png]        # one file
    python tools/ppm2png.py --dir screenshots/      # every *.ppm in a directory
"""

import argparse
import pathlib
import sys

try:
    from PIL import Image
except ImportError:  # pragma: no cover - environment guard
    sys.exit("Pillow is required: python -m pip install pillow")


def convert(src: pathlib.Path, dst: pathlib.Path) -> None:
    with Image.open(src) as im:
        im.convert("RGB").save(dst, format="PNG", optimize=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", help="input .ppm file")
    ap.add_argument("out", nargs="?", help="output .png file")
    ap.add_argument("--dir", help="convert every *.ppm in this directory")
    args = ap.parse_args()

    targets = []
    if args.dir:
        d = pathlib.Path(args.dir)
        for src in sorted(d.glob("*.ppm")):
            targets.append((src, src.with_suffix(".png")))
    elif args.path:
        src = pathlib.Path(args.path)
        dst = pathlib.Path(args.out) if args.out else src.with_suffix(".png")
        targets.append((src, dst))
    else:
        ap.error("give either a .ppm file or --dir")

    for src, dst in targets:
        convert(src, dst)
        print(f"{src.name} -> {dst.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
