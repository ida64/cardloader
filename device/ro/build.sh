#!/bin/sh
# Copy the hook-host sources into a cloned Atmosphère tree and build it.
# The hook in stratosphere/ro/source/impl/ro_service_impl.cpp must already be
# applied: `#include "ro_hh.hpp"`, and in ParseNro right after
# LocateAndApplyIpsPatchesToModule(...):
#     u64 program_id = 0;
#     std::memcpy(&program_id, module_id->data, sizeof(program_id));
#     if (program_id == 0x0100000000000000ULL)
#         R_TRY(ro::impl::InstallHookHost(m_process_handle, static_cast<u8 *>(mapped_memory)));
# Atmosphère 3e89150 needs libnx master (devkitpro/devkita64:libnx26); run
# `make clean` there after a toolchain change (LTO version errors otherwise).
set -e
ATMO=${ATMO:-/tmp/atmosphere}
RO="$ATMO/stratosphere/ro/source/impl"

cp device/ro/ro_hh.hpp device/ro/ro_hh.cpp "$RO/"
cp device/hookhost/hh_payload.h "$RO/"
cp device/hookhost/hh_payload.h "$ATMO/libraries/libmesosphere/include/kern_hh_payload.h"

# The ro-based hook is retired; the kernel performs the injection.
python3 tools/gen_kernel_data.py

docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$ATMO":/work -w /work devkitpro/devkita64:libnx26 make -j8
