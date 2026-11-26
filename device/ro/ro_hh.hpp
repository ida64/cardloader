#pragma once
#include <stratosphere.hpp>

namespace ams::ro::impl {
    /* Maps the hook-host payload and the test XCI into the target process,
     * writes the runtime config, and patches the FS 23.5.0 detours into the
     * caller's NRO mapping. No-op if the payload file is absent. */
    Result InstallHookHost(os::NativeHandle process_handle, u8 *mapped_nro);
}
