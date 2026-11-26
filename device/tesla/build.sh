#!/bin/sh
# Build the CardLoader Tesla overlay against a pinned libtesla.
#
#   sh device/tesla/build.sh
#
# Checks Tesla-Menu out at the pinned commit into a scratch directory outside
# this repository (SCRATCH, default /tmp/cardloader-tesla), verifies the libtesla
# submodule commit, builds device/tesla with devkitPro in docker, and stages
# xci-switcher.ovl plus SHA256SUMS in OUT (default work/tesla-overlay).
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

TESLA_MENU_URL=https://github.com/DefenderOfHyrule/Tesla-Menu.git
TESLA_MENU_COMMIT=198ad7e28ec481685cf9f68507fbc94fbd8bbb78 # "recompiled for 21.0.0 ABI changes", 2025-11-15
LIBTESLA_COMMIT=f766e9b607a05e9756843cbd62b3bfb98be1646c   # libs/libtesla submodule at that commit
IMAGE=devkitpro/devkita64:libnx26
SCRATCH=${SCRATCH:-/tmp/cardloader-tesla}
OUT=${OUT:-$ROOT/work/tesla-overlay}

if [ ! -d "$SCRATCH/.git" ]; then
    git clone --quiet "$TESLA_MENU_URL" "$SCRATCH"
fi
git -C "$SCRATCH" fetch --quiet origin
git -C "$SCRATCH" checkout --quiet --detach "$TESLA_MENU_COMMIT"
git -C "$SCRATCH" submodule update --init --quiet libs/libtesla
got=$(git -C "$SCRATCH/libs/libtesla" rev-parse HEAD)
if [ "$got" != "$LIBTESLA_COMMIT" ]; then
    echo "libtesla is at $got, expected $LIBTESLA_COMMIT" >&2
    exit 1
fi

# libtesla is header-only; building the overlay is what compiles it.
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$ROOT":/work -v "$SCRATCH":/tesla -w /work/device/tesla "$IMAGE" \
    make -j8 LIBTESLA=/tesla/libs/libtesla

mkdir -p "$OUT"
cp "$ROOT/device/tesla/xci-switcher.ovl" "$OUT/"
(cd "$OUT" && shasum -a 256 xci-switcher.ovl > SHA256SUMS && cat SHA256SUMS)
echo "Tesla-Menu $TESLA_MENU_COMMIT, libtesla $LIBTESLA_COMMIT"
