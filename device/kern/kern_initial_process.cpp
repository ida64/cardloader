/*
 * Copyright (c) Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <mesosphere.hpp>
#include "kern_hh_payload.h"

namespace ams::kern::impl {
    extern const u8 g_hh_payload[];
    extern const u8 g_hh_xci[];
}

namespace ams::kern {

    namespace {

        struct InitialProcessInfo {
            KProcess *process;
            size_t stack_size;
            s32 priority;
        };

        constinit KPhysicalAddress g_initial_process_binary_phys_addr = Null<KPhysicalAddress>;
        constinit KVirtualAddress g_initial_process_binary_address = Null<KVirtualAddress>;
        constinit size_t g_initial_process_binary_size = 0;
        constinit InitialProcessBinaryHeader g_initial_process_binary_header = {};
        constinit size_t g_initial_process_secure_memory_size = 0;
        constinit u64 g_initial_process_id_min = std::numeric_limits<u64>::max();
        constinit u64 g_initial_process_id_max = std::numeric_limits<u64>::min();

        /* Hook host for FS (23.5.0). The payload is position-independent and is
         * mapped into the FS process's alias-code region after creation. */
        constexpr u64 HookFsProgramId    = 0x0100000000000000ULL;
        constexpr size_t HookPayloadSize = HH_PAYLOAD_TOTAL;
        constexpr size_t HookXciSize     = 68096;
        constexpr size_t HookXciPages    = (HookXciSize + PageSize - 1) / PageSize;
        constexpr size_t HookMapSize     = HH_PAYLOAD_TOTAL + HookXciPages * PageSize;
        constexpr size_t HookTextSize    = HH_PAYLOAD_TEXT_SIZE;
        constexpr size_t HookRoSize      = HH_PAYLOAD_RO_SIZE;
        constexpr size_t HookDataSize    = HH_PAYLOAD_DATA_SIZE;
        constexpr u64 HookExecOffset     = HH_OFF_EXEC_TRAMP;
        constexpr u64 HookPresenceOffset = HH_OFF_PRESENCE_TRAMP;
        constexpr u64 HookEntryOffset    = HH_OFF_ENTRY_TRAMP;
        constexpr size_t HookRuntimeOffset = HH_OFF_RUNTIME - HH_PAYLOAD_DATA_VA;
        /* FS 23.5.0. The exFAT build has the same code 0xB200 further on. */
        constexpr u32 HookSiteExecutor   = 0x18C3B0;
        constexpr u32 HookSitePresence2  = 0x18F280; /* real inserted predicate */
        constexpr u32 HookSiteInitData   = 0x187A1C;
        constexpr u32 HookSiteCardCert   = 0x187B30; /* BL sub_18FDC0: card certificate RSA verify */
        constexpr u32 HookSiteShifts[]   = { 0, 0xB200 };
        constexpr struct { u32 offset; u32 insn; } HookSites[] = {
            { HookSiteExecutor,  0xD10403FFu }, /* SUB SP, SP, #0x100 */
            { HookSitePresence2, 0xA9BF7BFDu }, /* STP X29, X30, [SP, #-0x10]! */
            { HookSiteInitData,  0x9400265Du }, /* BL */
            { HookSiteCardCert,  0x940020A4u }, /* BL */
        };

        /* Out of line: the kernel image has to keep its size (tools/splice_mesosphere.py). */
        NOINLINE void HookWriteToPageGroup(KPageGroup &pg, size_t offset, const void *src, size_t size) {
            const u8 *s = static_cast<const u8 *>(src);
            size_t pos = 0;
            for (const auto &block : pg) {
                const size_t block_size = block.GetSize();
                const size_t block_end  = pos + block_size;
                if (offset < block_end && offset + size > pos) {
                    const size_t start = (offset > pos) ? (offset - pos) : 0;
                    const size_t end   = std::min(block_size, offset + size - pos);
                    u8 *dst = static_cast<u8 *>(GetVoidPointer(KMemoryLayout::GetLinearVirtualAddress(block.GetAddress())));
                    std::memcpy(dst + start, s + (pos + start - offset), end - start);
                }
                pos = block_end;
            }
        }

        NOINLINE void HookReadFromPageGroup(const KPageGroup &pg, size_t offset, void *dst, size_t size) {
            u8 *d = static_cast<u8 *>(dst);
            size_t pos = 0;
            for (const auto &block : pg) {
                const size_t block_size = block.GetSize();
                const size_t block_end  = pos + block_size;
                if (offset < block_end && offset + size > pos) {
                    const size_t start = (offset > pos) ? (offset - pos) : 0;
                    const size_t end   = std::min(block_size, offset + size - pos);
                    const u8 *src = static_cast<const u8 *>(GetVoidPointer(KMemoryLayout::GetLinearVirtualAddress(block.GetAddress())));
                    std::memcpy(d + (pos + start - offset), src + start, end - start);
                }
                pos = block_end;
            }
        }

        void HookCopyAndZero(KPageGroup &pg, const void *src, size_t size) {
            const u8 *s = static_cast<const u8 *>(src);
            size_t pos = 0;
            for (const auto &block : pg) {
                u8 *dst = static_cast<u8 *>(GetVoidPointer(KMemoryLayout::GetLinearVirtualAddress(block.GetAddress())));
                const size_t block_size = block.GetSize();
                for (size_t i = 0; i < block_size; i++, pos++) {
                    dst[i] = (pos < size) ? s[pos] : 0;
                }
            }
        }

        void HookEncodeDetour(u8 out[16], u64 target) {
            const u32 ldr = 0x58000050u; /* LDR X16, [PC, #8] */
            const u32 br  = 0xD61F0200u; /* BR  X16 */
            std::memcpy(out + 0, &ldr, sizeof(ldr));
            std::memcpy(out + 4, &br,  sizeof(br));
            std::memcpy(out + 8, &target, sizeof(target));
        }

        void LoadInitialProcessBinaryHeader() {
            if (g_initial_process_binary_header.magic != InitialProcessBinaryMagic) {
                /* Get the virtual address. */
                MESOSPHERE_INIT_ABORT_UNLESS(g_initial_process_binary_phys_addr != Null<KPhysicalAddress>);
                const KVirtualAddress virt_addr = KMemoryLayout::GetLinearVirtualAddress(g_initial_process_binary_phys_addr);

                /* Copy and validate the header. */
                g_initial_process_binary_header = *GetPointer<InitialProcessBinaryHeader>(virt_addr);
                MESOSPHERE_ABORT_UNLESS(g_initial_process_binary_header.magic == InitialProcessBinaryMagic);
                MESOSPHERE_ABORT_UNLESS(g_initial_process_binary_header.num_processes <= init::GetSlabResourceCounts().num_KProcess);

                /* Set the image address. */
                g_initial_process_binary_address = virt_addr;

                /* Process/calculate the secure memory size. */
                KVirtualAddress current = g_initial_process_binary_address + sizeof(InitialProcessBinaryHeader);
                const KVirtualAddress end = g_initial_process_binary_address + g_initial_process_binary_header.size;
                const size_t num_processes = g_initial_process_binary_header.num_processes;
                for (size_t i = 0; i < num_processes; ++i) {
                    /* Validate that we can read the current KIP. */
                    MESOSPHERE_ABORT_UNLESS(current <= end - sizeof(KInitialProcessHeader));

                    /* Attach to the current KIP. */
                    KInitialProcessReader reader;
                    KVirtualAddress data = reader.Attach(current);
                    MESOSPHERE_ABORT_UNLESS(data != Null<KVirtualAddress>);

                    /* If the process uses secure memory, account for that. */
                    if (reader.UsesSecureMemory()) {
                        g_initial_process_secure_memory_size += reader.GetSize() + util::AlignUp(reader.GetStackSize(), PageSize);
                    }

                    /* Advance to the next KIP. */
                    current = data + reader.GetBinarySize();
                }
            }
        }

        void CreateProcesses(InitialProcessInfo *infos) {
            /* Determine process image extents. */
            KVirtualAddress current = g_initial_process_binary_address + sizeof(InitialProcessBinaryHeader);
            KVirtualAddress end = g_initial_process_binary_address + g_initial_process_binary_header.size;

            /* Decide on pools to use. */
            const auto unsafe_pool = static_cast<KMemoryManager::Pool>(KSystemControl::GetCreateProcessMemoryPool());
            const auto secure_pool = (GetTargetFirmware() >= TargetFirmware_2_0_0) ? KMemoryManager::Pool_Secure : unsafe_pool;

            const size_t num_processes = g_initial_process_binary_header.num_processes;
            for (size_t i = 0; i < num_processes; ++i) {
                /* Validate that we can read the current KIP header. */
                MESOSPHERE_ABORT_UNLESS(current <= end - sizeof(KInitialProcessHeader));

                /* Attach to the current kip. */
                KInitialProcessReader reader;
                KVirtualAddress data = reader.Attach(current);
                MESOSPHERE_ABORT_UNLESS(data != Null<KVirtualAddress>);

                /* Ensure that the remainder of our parse is page aligned. */
                if (!util::IsAligned(GetInteger(data), PageSize)) {
                    const KVirtualAddress aligned_data = util::AlignDown(GetInteger(data), PageSize);
                    std::memmove(GetVoidPointer(aligned_data), GetVoidPointer(data), end - data);

                    data  = aligned_data;
                    end  -= (data - aligned_data);
                }

                /* If we crossed a page boundary, free the pages we're done using. */
                if (KVirtualAddress aligned_current = util::AlignDown(GetInteger(current), PageSize); aligned_current != data) {
                    const size_t freed_size = data - aligned_current;
                    Kernel::GetMemoryManager().Close(KMemoryLayout::GetLinearPhysicalAddress(aligned_current), freed_size / PageSize);
                    Kernel::GetSystemResourceLimit().Release(ams::svc::LimitableResource_PhysicalMemoryMax, freed_size);
                }

                /* Parse process parameters. */
                ams::svc::CreateProcessParameter params;
                MESOSPHERE_R_ABORT_UNLESS(reader.MakeCreateProcessParameter(std::addressof(params), true));

                /* Get the binary size for the kip. */
                const size_t binary_size  = reader.GetBinarySize();
                const size_t binary_pages = binary_size / PageSize;

                /* Get the pool for both the current (compressed) image, and the decompressed process. */
                const auto src_pool = Kernel::GetMemoryManager().GetPool(KMemoryLayout::GetLinearPhysicalAddress(data));
                const auto dst_pool = reader.UsesSecureMemory() ? secure_pool : unsafe_pool;

                /* Determine the process size, and how much memory isn't already reserved. */
                const size_t process_size    = params.code_num_pages * PageSize;
                const size_t unreserved_size = process_size - (src_pool == dst_pool ? util::AlignDown(binary_size, PageSize) : 0);

                /* Reserve however much memory we need to reserve. */
                MESOSPHERE_ABORT_UNLESS(Kernel::GetSystemResourceLimit().Reserve(ams::svc::LimitableResource_PhysicalMemoryMax, unreserved_size));

                /* Horizon places randomized heap/alias/stack regions directly after
                 * FS's code. Use the unused MapHuge gap before the code instead. */
                const bool is_fs = (params.program_id == HookFsProgramId);
                bool hook_fs = false;
                MESOSPHERE_ABORT_UNLESS(!is_fs || params.code_address >= HookMapSize);
                const KProcessAddress hook_va = is_fs ? util::AlignDown(params.code_address - HookMapSize, PageSize) : params.code_address;
                const u64 hook_base = GetInteger(hook_va);

                /* Create the process. */
                KProcess *new_process = nullptr;
                {
                    /* Make page groups to represent the data. */
                    KPageGroup pg(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());
                    KPageGroup workaround_pg(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());

                    /* Populate the page group to represent the data. */
                    {
                        /* Allocate the previously unreserved pages. */
                        KPageGroup unreserve_pg(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());
                        MESOSPHERE_R_ABORT_UNLESS(Kernel::GetMemoryManager().AllocateAndOpen(std::addressof(unreserve_pg), unreserved_size / PageSize, 1, KMemoryManager::EncodeOption(dst_pool, KMemoryManager::Direction_FromFront)));

                        /* Add the previously reserved pages. */
                        if (src_pool == dst_pool && binary_pages != 0) {
                            MESOSPHERE_R_ABORT_UNLESS(pg.AddBlock(KMemoryLayout::GetLinearPhysicalAddress(data), binary_pages));
                        }

                        /* Add the previously unreserved pages. */
                        for (const auto &block : unreserve_pg) {
                            MESOSPHERE_R_ABORT_UNLESS(pg.AddBlock(block.GetAddress(), block.GetNumPages()));
                        }
                    }
                    MESOSPHERE_ABORT_UNLESS(pg.GetNumPages() == static_cast<size_t>(params.code_num_pages));

                    /* Ensure that we do not leak pages. */
                    KPageGroup *process_pg = std::addressof(pg);
                    ON_SCOPE_EXIT { process_pg->Close(); };

                    /* Load the process. */
                    reader.Load(pg, data);

                    /* If necessary, close/release the aligned part of the data we just loaded. */
                    if (const size_t aligned_bin_size = util::AlignDown(binary_size, PageSize); aligned_bin_size != 0 && src_pool != dst_pool) {
                        Kernel::GetMemoryManager().Close(KMemoryLayout::GetLinearPhysicalAddress(data), aligned_bin_size / PageSize);
                        Kernel::GetSystemResourceLimit().Release(ams::svc::LimitableResource_PhysicalMemoryMax, aligned_bin_size);
                    }

                    /* Create a KProcess object. */
                    new_process = KProcess::Create();
                    MESOSPHERE_ABORT_UNLESS(new_process != nullptr);

                    /* Ensure the page group is usable for the process. */
                    /* If the pool is the same, we need to use the workaround page group. */
                    if (src_pool == dst_pool) {
                        /* Allocate a new, usable group for the process. */
                        MESOSPHERE_R_ABORT_UNLESS(Kernel::GetMemoryManager().AllocateAndOpen(std::addressof(workaround_pg), static_cast<size_t>(params.code_num_pages), 1, KMemoryManager::EncodeOption(dst_pool, KMemoryManager::Direction_FromFront)));

                        /* Copy data from the working page group to the usable one. */
                        auto work_it = pg.begin();
                        MESOSPHERE_ABORT_UNLESS(work_it != pg.end());
                        {
                            auto work_address   = work_it->GetAddress();
                            auto work_remaining = work_it->GetNumPages();
                            for (const auto &block : workaround_pg) {
                                auto block_address   = block.GetAddress();
                                auto block_remaining = block.GetNumPages();
                                while (block_remaining > 0) {
                                    if (work_remaining == 0) {
                                        ++work_it;
                                        work_address   = work_it->GetAddress();
                                        work_remaining = work_it->GetNumPages();
                                    }

                                    const size_t cur_pages = std::min(block_remaining, work_remaining);
                                    const size_t cur_size  = cur_pages * PageSize;
                                    std::memcpy(GetVoidPointer(KMemoryLayout::GetLinearVirtualAddress(block_address)), GetVoidPointer(KMemoryLayout::GetLinearVirtualAddress(work_address)), cur_size);

                                    block_address += cur_size;
                                    work_address  += cur_size;

                                    block_remaining -= cur_pages;
                                    work_remaining  -= cur_pages;
                                }
                            }

                            ++work_it;
                        }
                        MESOSPHERE_ABORT_UNLESS(work_it == pg.end());

                        /* We want to use the new page group. */
                        process_pg = std::addressof(workaround_pg);
                        pg.Close();
                    }

                    /* Patch the FS KIP text with detours to the hook host. An FS
                     * build whose sites are not recognised boots unhooked. */
                    if (is_fs) {
                        for (const u32 shift : HookSiteShifts) {
                            bool match = true;
                            for (const auto &site : HookSites) {
                                u32 insn = 0;
                                HookReadFromPageGroup(*process_pg, site.offset + shift, std::addressof(insn), sizeof(insn));
                                match = match && insn == site.insn;
                            }
                            if (!match) {
                                continue;
                            }

                            u8 detour[16];
                            HookEncodeDetour(detour, hook_base + HookExecOffset);
                            HookWriteToPageGroup(*process_pg, HookSiteExecutor + shift, detour, sizeof(detour));
                            HookEncodeDetour(detour, hook_base + HookPresenceOffset);
                            HookWriteToPageGroup(*process_pg, HookSitePresence2 + shift, detour, sizeof(detour));
                            const u32 mov_w0_0 = 0x52800000u; /* MOV W0, #0 */
                            HookWriteToPageGroup(*process_pg, HookSiteInitData + shift, std::addressof(mov_w0_0), sizeof(mov_w0_0));
                            HookWriteToPageGroup(*process_pg, HookSiteCardCert + shift, std::addressof(mov_w0_0), sizeof(mov_w0_0));

                            /* Initialize the hook host from crt0 in place of the bss memset. */
                            const u64 crt0_site = params.code_address + 0x30;
                            const s64 delta = static_cast<s64>(hook_base + HookEntryOffset) - static_cast<s64>(crt0_site);
                            const u32 bl = 0x94000000u | (static_cast<u32>(delta >> 2) & 0x3FFFFFFu);
                            HookWriteToPageGroup(*process_pg, 0x30, std::addressof(bl), sizeof(bl));

                            hook_fs = true;
                            break;
                        }
                    }

                    /* Initialize the process. */
                    MESOSPHERE_R_ABORT_UNLESS(new_process->Initialize(params, *process_pg, reader.GetCapabilities(), reader.GetNumCapabilities(), std::addressof(Kernel::GetSystemResourceLimit()), dst_pool, reader.IsImmortal()));
                }

                /* Set the process's memory permissions. */
                MESOSPHERE_R_ABORT_UNLESS(reader.SetMemoryPermissions(new_process->GetPageTable(), params));

                /* Map the hook host and test XCI into FS's alias-code region. */
                if (hook_fs) {
                    KPageGroup hh_text(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());
                    KPageGroup hh_ro(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());
                    KPageGroup hh_data(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());
                    KPageGroup hh_xci(Kernel::GetSystemSystemResource().GetBlockInfoManagerPointer());

                    MESOSPHERE_R_ABORT_UNLESS(Kernel::GetMemoryManager().AllocateAndOpen(std::addressof(hh_text), HookTextSize / PageSize, 1, KMemoryManager::EncodeOption(dst_pool, KMemoryManager::Direction_FromFront)));
                    MESOSPHERE_R_ABORT_UNLESS(Kernel::GetMemoryManager().AllocateAndOpen(std::addressof(hh_ro), HookRoSize / PageSize, 1, KMemoryManager::EncodeOption(dst_pool, KMemoryManager::Direction_FromFront)));
                    MESOSPHERE_R_ABORT_UNLESS(Kernel::GetMemoryManager().AllocateAndOpen(std::addressof(hh_data), HookDataSize / PageSize, 1, KMemoryManager::EncodeOption(dst_pool, KMemoryManager::Direction_FromFront)));
                    MESOSPHERE_R_ABORT_UNLESS(Kernel::GetMemoryManager().AllocateAndOpen(std::addressof(hh_xci), HookXciPages, 1, KMemoryManager::EncodeOption(dst_pool, KMemoryManager::Direction_FromFront)));

                    HookCopyAndZero(hh_text, impl::g_hh_payload, HookTextSize);
                    HookCopyAndZero(hh_ro, impl::g_hh_payload + HookTextSize, HookRoSize);
                    HookCopyAndZero(hh_data, impl::g_hh_payload + HookTextSize + HookRoSize, HookDataSize);
                    HookCopyAndZero(hh_xci, impl::g_hh_xci, HookXciSize);

                    struct HookRuntime {
                        u64 xci_addr;
                        u64 xci_size;
                        char path[256];
                    } runtime = { hook_base + HookPayloadSize, HookXciSize, "embedded" };
                    HookWriteToPageGroup(hh_data, HookRuntimeOffset, std::addressof(runtime), sizeof(runtime));

                    MESOSPHERE_R_ABORT_UNLESS(new_process->GetPageTable().MapPageGroup(hook_va, hh_text, KMemoryState_AliasCode, KMemoryPermission_UserReadExecute));
                    MESOSPHERE_R_ABORT_UNLESS(new_process->GetPageTable().MapPageGroup(hook_va + HookTextSize, hh_ro, KMemoryState_AliasCode, KMemoryPermission_UserRead));
                    MESOSPHERE_R_ABORT_UNLESS(new_process->GetPageTable().MapPageGroup(hook_va + HookTextSize + HookRoSize, hh_data, KMemoryState_AliasCodeData, KMemoryPermission_UserReadWrite));
                    MESOSPHERE_R_ABORT_UNLESS(new_process->GetPageTable().MapPageGroup(hook_va + HookPayloadSize, hh_xci, KMemoryState_AliasCodeData, KMemoryPermission_UserReadWrite));
                }

                /* Register the process. */
                KProcess::Register(new_process);

                /* Set the ideal core id. */
                new_process->SetIdealCoreId(reader.GetIdealCoreId());

                /* Save the process info. */
                infos[i].process    = new_process;
                infos[i].stack_size = reader.GetStackSize();
                infos[i].priority   = reader.GetPriority();

                /* Advance the reader. */
                current = data + binary_size;
            }

            /* Release remaining memory used by the image. */
            {
                const size_t remaining_size  = util::AlignUp(GetInteger(g_initial_process_binary_address) + g_initial_process_binary_header.size, PageSize) - util::AlignDown(GetInteger(current), PageSize);
                const size_t remaining_pages = remaining_size / PageSize;
                Kernel::GetMemoryManager().Close(KMemoryLayout::GetLinearPhysicalAddress(util::AlignDown(GetInteger(current), PageSize)), remaining_pages);
                Kernel::GetSystemResourceLimit().Release(ams::svc::LimitableResource_PhysicalMemoryMax, remaining_size);
            }
        }

    }

    void SetInitialProcessBinaryPhysicalAddress(KPhysicalAddress phys_addr, size_t size) {
        MESOSPHERE_INIT_ABORT_UNLESS(g_initial_process_binary_phys_addr == Null<KPhysicalAddress>);

        g_initial_process_binary_phys_addr = phys_addr;
        g_initial_process_binary_size      = size;
    }

    KPhysicalAddress GetInitialProcessBinaryPhysicalAddress() {
        MESOSPHERE_INIT_ABORT_UNLESS(g_initial_process_binary_phys_addr != Null<KPhysicalAddress>);

        return g_initial_process_binary_phys_addr;
    }

    size_t GetInitialProcessBinarySize() {
        MESOSPHERE_INIT_ABORT_UNLESS(g_initial_process_binary_phys_addr != Null<KPhysicalAddress>);

        return g_initial_process_binary_size;
    }

    u64 GetInitialProcessIdMin() {
        return g_initial_process_id_min;
    }

    u64 GetInitialProcessIdMax() {
        return g_initial_process_id_max;
    }

    size_t GetInitialProcessesSecureMemorySize() {
        LoadInitialProcessBinaryHeader();

        return g_initial_process_secure_memory_size;
    }

    size_t CopyInitialProcessBinaryToKernelMemory() {
        LoadInitialProcessBinaryHeader();

        if (g_initial_process_binary_header.num_processes > 0) {
            /* Ensure that we have a non-zero size. */
            const size_t expected_size = g_initial_process_binary_size;
            MESOSPHERE_INIT_ABORT_UNLESS(expected_size != 0);

            /* Ensure that the size we need to reserve is as we expect it to be. */
            const u32 total_size = util::AlignUp(g_initial_process_binary_header.size, PageSize);
            MESOSPHERE_ABORT_UNLESS(total_size == expected_size);
            MESOSPHERE_ABORT_UNLESS(total_size <= InitialProcessBinarySizeMax);

            /* Reserve pages for the initial process binary from the system resource limit. */
            MESOSPHERE_ABORT_UNLESS(Kernel::GetSystemResourceLimit().Reserve(ams::svc::LimitableResource_PhysicalMemoryMax, total_size));

            return total_size;
        } else {
            return 0;
        }
    }

    void CreateAndRunInitialProcesses() {
        /* Allocate space for the processes. */
        InitialProcessInfo *infos = static_cast<InitialProcessInfo *>(__builtin_alloca(sizeof(InitialProcessInfo) * g_initial_process_binary_header.num_processes));

        /* Create the processes. */
        CreateProcesses(infos);

        /* Determine the initial process id range. */
        for (size_t i = 0; i < g_initial_process_binary_header.num_processes; i++) {
            const auto pid = infos[i].process->GetId();
            g_initial_process_id_min = std::min(g_initial_process_id_min, pid);
            g_initial_process_id_max = std::max(g_initial_process_id_max, pid);
        }

        /* Run the processes. */
        for (size_t i = 0; i < g_initial_process_binary_header.num_processes; i++) {
            MESOSPHERE_R_ABORT_UNLESS(infos[i].process->Run(infos[i].priority, infos[i].stack_size));
            infos[i].process->Close();
        }
    }

}
