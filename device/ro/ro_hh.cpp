#include <stratosphere.hpp>
#include "ro_hh.hpp"
#include "ro_random.hpp"
#include "hh_payload.h"

namespace ams::ro::impl {

    namespace {

        constexpr const char *PayloadPath = "sdmc:/switch/CardLoader/hookhost.bin";
        constexpr const char *ConfigPath  = "sdmc:/switch/CardLoader/mount.cfg";
        constexpr const char *XciPath     = "sdmc:/switch/CardLoader/mount.xci";
        constexpr size_t XciMaxSize       = 1 * 1024 * 1024;
        constexpr size_t PageSize         = 0x1000;
        constexpr u64 FsProgramId         = 0x0100000000000000ULL;

        /* Must match hh_runtime_t in device/hookhost/hh.h. */
        struct HookRuntime {
            u64 xci_addr;
            u64 xci_size;
            char path[256];
        };
        static_assert(sizeof(HookRuntime) == 0x110);

        /* FS 23.5.0 sites. */
        constexpr u32 SiteExecutor     = 0x18C3B0;
        constexpr u32 SitePresence     = 0x18D1E0;
        constexpr u32 SiteInitDataCall = 0x187A1C;

        alignas(PageSize) u8 g_payload[HH_PAYLOAD_TOTAL];
        alignas(PageSize) u8 g_xci[XciMaxSize];
        bool g_done;

        size_t ReadWholeFile(const char *path, u8 *dst, size_t cap) {
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(&f, path, fs::OpenMode_Read))) {
                return 0;
            }
            ON_SCOPE_EXIT { fs::CloseFile(f); };

            s64 size = 0;
            if (R_FAILED(fs::GetFileSize(&size, f)) || size <= 0 || static_cast<size_t>(size) > cap) {
                return 0;
            }

            size_t got = 0;
            if (R_FAILED(fs::ReadFile(&got, f, 0, dst, static_cast<size_t>(size)))) {
                return 0;
            }
            return got;
        }

        void LogLine(const char *text) {
            constexpr const char *LogPath = "sdmc:/switch/CardLoader/ro.log";
            const size_t len = std::strlen(text);
            fs::DeleteFile(LogPath);
            if (R_FAILED(fs::CreateFile(LogPath, static_cast<s64>(len)))) {
                return;
            }
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(&f, LogPath, fs::OpenMode_Write))) {
                return;
            }
            ON_SCOPE_EXIT { fs::CloseFile(f); };
            fs::WriteFile(f, 0, text, len, fs::WriteOption::Flush);
        }

        void EncodeDetour(u8 *p, u64 target) {
            const u32 ldr = 0x58000050u; /* LDR X16, [PC, #8] */
            const u32 br  = 0xD61F0200u; /* BR  X16 */
            std::memcpy(p + 0, &ldr, sizeof(ldr));
            std::memcpy(p + 4, &br, sizeof(br));
            std::memcpy(p + 8, &target, sizeof(target));
        }

    }

    Result InstallHookHost(os::NativeHandle process_handle, u8 *mapped_nro) {
        if (g_done) {
            return ResultSuccess();
        }
        g_done = true;
        LogLine("hh: enter\n");

        /* Read the payload; absent file means "feature off". */
        const size_t payload_size = ReadWholeFile(PayloadPath, g_payload, sizeof(g_payload));
        if (payload_size == 0) {
            LogLine("hh: no payload\n");
            return ResultSuccess();
        }
        if (payload_size > HH_PAYLOAD_FILE_SIZE) {
            return ResultSuccess();
        }

        const size_t xci_size = ReadWholeFile(XciPath, g_xci, sizeof(g_xci));

        char cfg[sizeof(HookRuntime::path)] = {};
        size_t cfg_len = ReadWholeFile(ConfigPath, reinterpret_cast<u8 *>(cfg), sizeof(cfg) - 1);
        while (cfg_len > 0 && (cfg[cfg_len - 1] == '\n' || cfg[cfg_len - 1] == '\r')) {
            cfg[--cfg_len] = 0;
        }

        auto *runtime = reinterpret_cast<HookRuntime *>(g_payload + HH_OFF_RUNTIME);
        runtime->xci_size = xci_size;
        if (cfg_len > 0) {
            std::memcpy(runtime->path, cfg, cfg_len);
        }

        /* Map the payload (text + rodata + data + bss) into the target. */
        os::ProcessMemoryRegion region = { reinterpret_cast<u64>(g_payload), HH_PAYLOAD_TOTAL };
        u64 base = 0;
        R_TRY(os::MapProcessCodeMemory(&base, process_handle, &region, 1, ro::impl::GenerateSecureRandom));

        R_TRY(os::SetProcessMemoryPermission(process_handle, base + HH_PAYLOAD_TEXT_VA, HH_PAYLOAD_TEXT_SIZE, os::MemoryPermission_ReadExecute));
        R_TRY(os::SetProcessMemoryPermission(process_handle, base + HH_PAYLOAD_RO_VA,   HH_PAYLOAD_RO_SIZE,   os::MemoryPermission_ReadOnly));
        R_TRY(os::SetProcessMemoryPermission(process_handle, base + HH_PAYLOAD_DATA_VA, HH_PAYLOAD_DATA_SIZE, os::MemoryPermission_ReadWrite));

        /* Optional memory-backed test XCI. */
        if (xci_size > 0) {
            const u64 map_size = util::AlignUp(static_cast<u64>(xci_size), static_cast<u64>(PageSize));
            os::ProcessMemoryRegion xregion = { reinterpret_cast<u64>(g_xci), map_size };
            u64 xbase = 0;
            R_TRY(os::MapProcessCodeMemory(&xbase, process_handle, &xregion, 1, ro::impl::GenerateSecureRandom));
            R_TRY(os::SetProcessMemoryPermission(process_handle, xbase, map_size, os::MemoryPermission_ReadWrite));
            runtime->xci_addr = xbase;
        }

        /* Patch FS. The mapped NRO is shared with the target. */
        EncodeDetour(mapped_nro + SiteExecutor,     base + HH_OFF_EXEC_TRAMP);
        EncodeDetour(mapped_nro + SitePresence,     base + HH_OFF_PRESENCE_TRAMP);
        const u32 mov_w0_0 = 0x52800000u; /* MOV W0, #0 */
        std::memcpy(mapped_nro + SiteInitDataCall, &mov_w0_0, sizeof(mov_w0_0));

        char msg[160];
        util::SNPrintf(msg, sizeof(msg),
            "hh: payload=%zu xci=%zu base=0x%lx xci_base=0x%lx\n",
            payload_size, xci_size,
            static_cast<unsigned long>(base),
            static_cast<unsigned long>(runtime->xci_addr));
        LogLine(msg);

        return ResultSuccess();
    }

}
