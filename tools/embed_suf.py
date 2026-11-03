"""Generate a freestanding C header containing a validated SUF asset."""

import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    source = pathlib.Path(sys.argv[1])
    target = pathlib.Path(sys.argv[2])
    data = source.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="ascii", newline="\n") as output:
        output.write("#ifndef OW_TERMINAL_FONT_H\n#define OW_TERMINAL_FONT_H\n")
        output.write("#include <stddef.h>\n#include <stdint.h>\n")
        output.write("static const uint8_t ow_terminal_font_data[] = {\n")
        for offset in range(0, len(data), 12):
            output.write("    ")
            output.write(", ".join(f"0x{value:02X}u" for value in data[offset:offset + 12]))
            output.write(",\n")
        output.write("};\n")
        output.write("static const size_t ow_terminal_font_size = "
                     "sizeof(ow_terminal_font_data);\n")
        output.write("#endif\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
