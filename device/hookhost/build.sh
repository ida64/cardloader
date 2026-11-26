#!/bin/sh
# Cross-build the hook-host payload. Works with devkitA64's gcc inside the
# devkitpro/devkita64 image, or with clang + lld on the host.
set -e
CC=${CC:-clang}
OUT=${OUT:-build/hookhost.elf}
case "$CC" in
  *gcc*)
    TARGET="-mcpu=cortex-a57"
    PATH="${DEVKITPRO:-/opt/devkitpro}/devkitA64/bin:$PATH"
    export PATH
    ;;
  *)
    TARGET="--target=aarch64-none-elf"
    ;;
esac
SRC="core/crypto.c core/image.c core/xci.c core/lotus3.c core/gc_cert.c core/asic.c core/fat.c core/mount.c
     device/hookhost/hh_layout.c device/hookhost/hh_glue.c device/hookhost/hh_window.c device/hookhost/hh_swap.c
     device/hookhost/hh_libc.c device/hookhost/hh_tramp.S"
DP=${DEVKITPRO:-/opt/devkitpro}
$CC $TARGET -ffreestanding -nostdlib -std=c11 -O2 \
    -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -ffunction-sections -fdata-sections \
    -Icore -Idevice/hookhost -isystem device/hookhost/shim \
    -I"$DP/libnx/include" \
    $SRC -L"$DP/libnx/lib" -lnx \
    -Wl,-T,device/hookhost/hh.ld -Wl,-e,hh_init -Wl,--gc-sections -o "$OUT"
echo "built $OUT ($(wc -c < "$OUT") bytes)"
# The kernel embeds the flat image (tools/gen_kernel_data.py reads it), so
# regenerate it here or a stale payload would be spliced into mesosphere.
if command -v aarch64-none-elf-objcopy >/dev/null 2>&1; then
    BIN="${OUT%.elf}.bin"
    aarch64-none-elf-objcopy -O binary "$OUT" "$BIN"
    echo "built $BIN ($(wc -c < "$BIN") bytes)"
fi
