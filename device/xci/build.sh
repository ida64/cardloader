#!/bin/sh
# Build the xci mount sysmodule inside the Atmosphère tree via the
# devkitpro container.  The module reuses memlet's Makefile/system_module.mk.
set -e
ATMO=${ATMO:-/tmp/atmosphere}
DEST="$ATMO/stratosphere/xci"

[ -d "$ATMO" ] || { echo "missing Atmosphère tree at $ATMO" >&2; exit 1; }

mkdir -p "$DEST/source"
rm -rf "$DEST/source"/*
cp device/xci/source/*.cpp device/xci/source/*.hpp device/xci/source/*.c device/xci/source/*.h "$DEST/source/"
cp device/hookhost/hh_window.h "$DEST/source/"
cp "$ATMO/stratosphere/memlet/Makefile" "$ATMO/stratosphere/memlet/system_module.mk" "$DEST/"
cp device/xci/xci.json "$DEST/"

docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$ATMO":/work -w /work devkitpro/devkita64:libnx26 \
    make -C stratosphere/xci -j8
