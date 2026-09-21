#!/usr/bin/env python3
"""Package the Essentials owinit executable and emit a C byte-array header."""
import argparse
import pathlib
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--packer", default="tools/owx_pack.py")
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    output_path = pathlib.Path(args.output)
    if not input_path.is_file():
        raise SystemExit(f"missing owinit input: {input_path}")

    packaged = output_path.with_suffix(".owx")
    subprocess.run(
        [sys.executable, args.packer, str(input_path), str(packaged), "--subsystem", "0x04"],
        check=True,
    )
    data = packaged.read_bytes()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="ascii", newline="\n") as header:
        header.write("/* Generated from OpenWindows-Essentials/Software/owinit/owinit.c. */\n")
        header.write("#ifndef OWINIT_IMAGE_GENERATED_H\n#define OWINIT_IMAGE_GENERATED_H\n")
        header.write(f"#define OWINIT_IMAGE_SIZE {len(data)}U\n")
        header.write("static const unsigned char g_owinit_image[] = {\n")
        for offset in range(0, len(data), 12):
            row = ", ".join(f"0x{byte:02X}" for byte in data[offset:offset + 12])
            header.write(f"    {row},\n")
        header.write("};\n#endif\n")


if __name__ == "__main__":
    main()
