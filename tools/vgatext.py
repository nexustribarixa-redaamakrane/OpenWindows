#!/usr/bin/env python3
"""Decode a raw VGA text-mode dump into plain text.

Input is a ``pmemsave 0xb8000 4000`` dump: 80x25 cells, each a (char, attr)
byte pair, character code page 437.  Output is the visible text, one line per
screen row, so a screenshot's content can be checked without eyeballing it.

Usage:
    python tools/vgatext.py dump.vgabin [--attrs] [-o out.txt]
"""

import argparse
import sys

COLS = 80
ROWS = 25
CELL = 2
BYTES = COLS * ROWS * CELL


def decode(data: bytes):
    if len(data) < BYTES:
        raise SystemExit(f"expected {BYTES} bytes, got {len(data)}")
    lines, attrs = [], []
    for row in range(ROWS):
        base = row * COLS * CELL
        chars = []
        row_attrs = set()
        for col in range(COLS):
            i = base + col * CELL
            ch = data[i]
            row_attrs.add(data[i + 1])
            # CP437 maps 0x00-0x1F to control glyphs; show blanks for NULs.
            chars.append(chr(ch) if ch >= 0x20 else (" " if ch == 0 else "."))
        lines.append("".join(chars).rstrip())
        attrs.append(sorted(row_attrs))
    return lines, attrs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump", help="4000-byte VGA text dump from pmemsave")
    ap.add_argument("-o", "--out", help="write text here instead of stdout")
    ap.add_argument("--attrs", action="store_true",
                    help="also report the attribute bytes used per row")
    args = ap.parse_args()

    with open(args.dump, "rb") as fh:
        data = fh.read()
    lines, attrs = decode(data)

    out = "\n".join(lines) + "\n"
    if args.attrs:
        out += "\n-- attributes (row: byte set) --\n"
        for row, a in enumerate(attrs):
            out += f"{row:2d}: " + " ".join(f"{b:02X}" for b in a) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
