#!/bin/sh
# Build package3 with the FS hook host from source.
#
#   ATMD=/path/to/Atmosphere sh device/kern/build.sh <package3 in> <package3 out>
#
# <package3 in> supplies everything except mesosphere (exosphere, fusee, INI1
# KIPs, splash); use the console's stock package3.orig. The Atmosphere tree must
# be at the same revision that build came from (3e8915011 for 23.5.0/1.12.2).
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ATMD=${ATMD:-/tmp/atmosphere}
MESO="$ATMD/libraries/libmesosphere"

test -d "$MESO" || { echo "no libmesosphere under $ATMD" >&2; exit 1; }

# 1. FS hook in the kernel's initial-process creation.
cp "$ROOT/device/kern/kern_initial_process.cpp" "$MESO/source/kern_initial_process.cpp"

# 2. Payload. The kernel jumps to offsets inside it (trampolines, runtime), so
# hh_payload.h must be regenerated from this build before the kernel compiles.
docker run --rm -v "$ROOT":/work -w /work devkitpro/devkita64:libnx26 \
    bash -lc 'CC=aarch64-none-elf-gcc sh device/hookhost/build.sh'
python3 "$ROOT/tools/gen_hh_layout.py"
cp "$ROOT/device/hookhost/hh_payload.h"        "$MESO/include/kern_hh_payload.h"

# 3. Test XCI as kernel data (g_hh_xci), payload blob from build/hookhost.bin.
python3 "$ROOT/tools/gen_kernel_data.py"

# 4. Kernel.
docker run --rm -v "$ATMD":/ams -w /ams/mesosphere devkitpro/devkita64:libnx26 \
    bash -lc 'make -j8'

# 4. Swap the kernel into the package.
python3 "$ROOT/tools/splice_mesosphere.py" "$1" \
    "$ATMD/mesosphere/out/nintendo_nx_arm64_armv8a/release/mesosphere.bin" "$2"
