#!/usr/bin/env python3
"""Replace the mesosphere section of an Atmosphere package3.

package3 layout (fusee/build_package3.py): header at 0x0, mesosphere at 0x56000,
its size in the header at 0x0C. The size must stay the same, otherwise every
later section would move; mesosphere.bin is page-padded to a fixed size by the
build, so this holds for kernels of the same configuration.

Usage: splice_mesosphere.py <package3 in> <mesosphere.bin> <package3 out>
"""
import struct
import sys

MESOSPHERE_OFFSET = 0x56000
HEADER_SIZE_FIELD = 0x0C


def main() -> int:
    src, meso_path, dst = sys.argv[1:4]
    image = bytearray(open(src, "rb").read())
    meso = open(meso_path, "rb").read()
    if image[:4] != b"PK31":
        raise SystemExit("not a package3 (missing PK31 magic)")
    size = struct.unpack_from("<I", image, HEADER_SIZE_FIELD)[0]
    if size != len(meso):
        raise SystemExit(f"mesosphere size changed: package3 has {size:#x}, new image is {len(meso):#x}; "
                         "refusing to shift the remaining sections")
    image[MESOSPHERE_OFFSET:MESOSPHERE_OFFSET + size] = meso
    open(dst, "wb").write(image)
    print(f"mesosphere @ {MESOSPHERE_OFFSET:#x}, {size:#x} bytes -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
