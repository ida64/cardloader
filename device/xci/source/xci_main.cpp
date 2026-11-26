#include <stratosphere.hpp>
#include "xci_service.hpp"
#include "hh_window.h"
#include "xci_lib.h"

/* Window ABI shared with the FS hook. device/hookhost/hh_glue.c asserts the
 * same offsets, so a header change that is not rebuilt into both halves fails
 * to compile instead of silently logging garbage. */
static_assert(offsetof(hh_window_t, total) == 0x10);
static_assert(offsetof(hh_window_t, data) == 0x18);
static_assert(offsetof(hh_window_t, stage) == 0x20018);
static_assert(offsetof(hh_window_t, exec_count) == 0x20024);
static_assert(offsetof(hh_window_t, exec_last) == 0x20028);
static_assert(offsetof(hh_window_t, trace_seq) == 0x2002C);
static_assert(offsetof(hh_window_t, trace) == 0x20030);
static_assert(sizeof(hh_trace_t) == 28);
static_assert(offsetof(hh_window_t, swap_req) == 0x20730);
static_assert(offsetof(hh_window_t, swap_ack) == 0x20734);
static_assert(offsetof(hh_window_t, swap_done) == 0x20738);
static_assert(offsetof(hh_window_t, mount_code) == 0x2073C);
static_assert(sizeof(hh_window_t) == 0x20740);
static_assert(sizeof(hh_window_t) <= HH_WINDOW_SIZE);
static_assert(sizeof(XciImageEntry) == 0x90);
static_assert(sizeof(XciStatus) == 0x20);

namespace ams::xci {

    os::NativeHandle g_shmem_handle;
    std::atomic<u32> g_window_requests;

    namespace {

        constexpr const char *LibraryPath = "sdmc:/switch/CardLoader/library.cfg";
        constexpr const char *LibraryDir  = "sdmc:/xci/";
        constexpr const char *LogPath     = "sdmc:/switch/CardLoader/xci.log";
        constexpr size_t WindowSize  = HH_WINDOW_SIZE;
        constexpr size_t PageSize    = HH_WINDOW_PAGE_SIZE;
        constexpr int    MaxLogLines = 1000;
        constexpr u32    LogPeriodMs = 250;
        constexpr size_t MaxOpenFiles = 8; /* current + staged parts, a probe */

        /* The heap and alias regions are placed at random and reject shared
         * mappings, so step down until one address is accepted. */
        constexpr u64 WindowAddressStep  = 0x800000000ULL;
        constexpr int WindowAddressTries = 8;

        constinit os::SharedMemoryType g_shared_memory = {};
        hh_window_t *g_window;

        /* One lock over the library state: the reader serves pages and
         * completes swaps under it, IPC handlers list and stage under it. */
        constinit os::SdkMutex g_lock;
        constinit os::SdkMutex g_log_lock;
        xci_server_t g_srv;

        /* fsp-srv cannot fill the window directly: the kernel refuses IPC
         * buffers inside shared memory, so every read goes through this page. */
        alignas(0x1000) u8 g_page[PageSize];

        fs::FileHandle g_files[MaxOpenFiles];
        bool g_file_used[MaxOpenFiles];
        fs::DirectoryEntry g_dir_entries[8];

        s64 g_log_size;
        int g_log_lines;

        os::ThreadType g_reader;
        alignas(os::ThreadStackAlignment) u8 g_reader_stack[0x4000];

        constexpr size_t NumServers  = 1;
        constexpr size_t NumSessions = 4; /* the FS hook's GetWindow, clients */
        sf::hipc::ServerManager<NumServers, sf::hipc::DefaultServerManagerOptions, NumSessions> g_server_manager;
        constinit sf::UnmanagedServiceObject<xci::impl::IService, xci::Service> g_service_object;

        /* Lowercase hex, 2 chars per byte, null terminated. */
        void Hex(char *dst, const u8 *src, size_t n) {
            constexpr char digits[] = "0123456789abcdef";
            for (size_t i = 0; i < n; i++) {
                dst[2 * i]     = digits[src[i] >> 4];
                dst[2 * i + 1] = digits[src[i] & 0xF];
            }
            dst[2 * n] = 0;
        }

        /* Appends one line to the SD log. */
        void Log(const char *fmt, ...) {
            std::scoped_lock lk(g_log_lock);
            if (g_log_lines >= MaxLogLines) {
                return;
            }
            char line[192];
            std::va_list vl;
            va_start(vl, fmt);
            const int len = util::VSNPrintf(line, sizeof(line), fmt, vl);
            va_end(vl);
            if (len <= 0) {
                return;
            }
            const size_t size = std::min(static_cast<size_t>(len), sizeof(line) - 1);

            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), LogPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                return;
            }
            if (R_SUCCEEDED(fs::WriteFile(f, g_log_size, line, size, fs::WriteOption::Flush))) {
                g_log_size += size;
                g_log_lines++;
            }
            fs::CloseFile(f);
        }

        int FsOpen(void *, const char *path, void **file, uint64_t *size) {
            size_t slot = 0;
            while (slot < MaxOpenFiles && g_file_used[slot]) {
                slot++;
            }
            if (slot == MaxOpenFiles) {
                return -1;
            }
            fs::FileHandle *f = std::addressof(g_files[slot]);
            if (R_FAILED(fs::OpenFile(f, path, fs::OpenMode_Read))) {
                return -1;
            }
            s64 sz = 0;
            if (R_FAILED(fs::GetFileSize(std::addressof(sz), *f))) {
                fs::CloseFile(*f);
                return -1;
            }
            g_file_used[slot] = true;
            *file = f;
            *size = static_cast<uint64_t>(sz);
            return 0;
        }

        void FsClose(void *, void *file) {
            fs::FileHandle *f = static_cast<fs::FileHandle *>(file);
            fs::CloseFile(*f);
            g_file_used[f - g_files] = false;
        }

        int FsRead(void *, void *file, uint64_t off, void *buf, size_t n) {
            const fs::FileHandle f = *static_cast<fs::FileHandle *>(file);
            u8 *dst = static_cast<u8 *>(buf);
            while (n > 0) {
                const size_t chunk = std::min(n, PageSize);
                size_t got = 0;
                const Result rc = fs::ReadFile(std::addressof(got), f, static_cast<s64>(off), g_page, chunk);
                if (R_FAILED(rc) || got == 0) {
                    return R_FAILED(rc) ? static_cast<int>(rc.GetValue()) : -1;
                }
                std::memcpy(dst, g_page, got);
                dst += got;
                off += got;
                n -= got;
            }
            return 0;
        }

        int FsList(void *, const char *dir, void (*add)(void *, const char *, uint64_t), void *cookie) {
            /* fs wants the directory without the trailing slash, except the root. */
            char path[XCI_PATH_MAX];
            util::Strlcpy(path, dir, sizeof(path));
            size_t n = std::strlen(path);
            if (n > 6 && path[n - 1] == '/') {
                path[n - 1] = 0;
            }
            fs::DirectoryHandle d;
            if (R_FAILED(fs::OpenDirectory(std::addressof(d), path, fs::OpenDirectoryMode_File))) {
                return -1;
            }
            while (true) {
                s64 count = 0;
                if (R_FAILED(fs::ReadDirectory(std::addressof(count), g_dir_entries, d, util::size(g_dir_entries))) || count <= 0) {
                    break;
                }
                for (s64 i = 0; i < count; i++) {
                    add(cookie, g_dir_entries[i].name, static_cast<uint64_t>(g_dir_entries[i].file_size));
                }
            }
            fs::CloseDirectory(d);
            return 0;
        }

        constinit const xci_fs_t g_fs = { FsOpen, FsClose, FsRead, FsList, nullptr };

        Result ToResult(int code) {
            switch (code) {
                case 0:                      R_SUCCEED();
                case XciError_InvalidIndex:  R_THROW(xci::ResultInvalidIndex());
                case XciError_InvalidPath:   R_THROW(xci::ResultInvalidPath());
                case XciError_OpenFailed:    R_THROW(xci::ResultOpenFailed());
                case XciError_Busy:          R_THROW(xci::ResultBusy());
                case XciError_GameCardInUse: R_THROW(xci::ResultGameCardInUse());
                case XciError_ListFailed:    R_THROW(xci::ResultListFailed());
                default:                     R_THROW(xci::ResultNotAnImage());
            }
        }

        /* Swap policy: refuse while an application launched from the game card
         * runs. Removing the card under it invalidates its storage handles
         * (docs/fs-23.5.0.md, "Hot swap"). Homebrew running through a title
         * override counts as not using the card. */
        bool GameCardApplicationRunning() {
            if (R_FAILED(pmdmntInitialize())) {
                Log("swap: pm:dmnt unavailable, refusing\n");
                return true;
            }
            os::ProcessId pid;
            const Result app = pm::dmnt::GetApplicationProcessId(std::addressof(pid));
            pmdmntExit();
            if (R_FAILED(app)) {
                return false; /* no application */
            }
            if (R_FAILED(pminfoInitialize())) {
                Log("swap: pm:info unavailable, refusing\n");
                return true;
            }
            ncm::ProgramLocation loc;
            cfg::OverrideStatus status;
            const Result info = pm::info::GetProcessInfo(std::addressof(loc), std::addressof(status), pid);
            pminfoExit();
            if (R_FAILED(info)) {
                return true;
            }
            return loc.storage_id == static_cast<u8>(ncm::StorageId::GameCard) && !status.IsHbl();
        }

        Result Select(const char *what, int (*op)(const char *, u32), const char *path, u32 index) {
            if (GameCardApplicationRunning()) {
                Log("swap: refused (%s): game card application running\n", what);
                R_THROW(xci::ResultGameCardInUse());
            }
            int rc;
            {
                std::scoped_lock lk(g_lock);
                rc = op(path, index);
            }
            if (rc == 0) {
                Log("swap: select %s -> gen=%u image=%s total=0x%lx\n", what, g_window->swap_req,
                    g_srv.staged.name, static_cast<unsigned long>(g_srv.staged.total));
            } else {
                Log("swap: select %s failed error=%d\n", what, rc);
            }
            R_RETURN(ToResult(rc));
        }

        /* What the FS hook has done so far, as seen from this side. */
        struct HookState {
            u32 requests;
            u32 stage;
            u32 presence_calls;
            u32 presence_hits;
            u32 exec_count;
            u32 exec_last;
            u32 read_failures;
            s32 mount_code;

            bool operator==(const HookState &) const = default;
        };

        void ReaderThread(void *) {
            hh_window_t *w = g_window;
            u32 trace_seen = 0;
            HookState logged = {};
            u32 quiet_ms = LogPeriodMs;
            while (true) {
                u32 done_before, done_after;
                {
                    std::scoped_lock lk(g_lock);
                    done_before = w->swap_done;
                    xci_server_step(std::addressof(g_srv), w);
                    done_after = w->swap_done;
                }
                if (done_after != done_before) {
                    Log("swap: done gen=%u image=%s total=0x%lx\n", done_after, g_srv.cur.name,
                        static_cast<unsigned long>(g_srv.cur.total));
                }

                if (quiet_ms < LogPeriodMs) {
                    quiet_ms++;
                } else {
                    const HookState now = { g_window_requests.load(), w->stage, w->presence_calls, w->presence_hits, w->exec_count, w->exec_last, g_srv.read_failures, w->mount_code };
                    if (now != logged) {
                        Log("hook: window=%u stage=%u presence=%u/%u exec=%u last=0x%04x reads=%u readfail=%u rc=0x%x mount=%d\n",
                            now.requests, now.stage, now.presence_hits, now.presence_calls, now.exec_count, now.exec_last, g_srv.served, now.read_failures, static_cast<u32>(g_srv.read_error), now.mount_code);
                        logged = now;
                        quiet_ms = 0;
                    }

                    /* Every ASIC operation since the last tick. */
                    const u32 tseq = __atomic_load_n(&w->trace_seq, __ATOMIC_ACQUIRE);
                    if (tseq - trace_seen > HH_TRACE_LEN) {
                        Log("trace: %u ops dropped\n", tseq - trace_seen - HH_TRACE_LEN);
                        trace_seen = tseq - HH_TRACE_LEN;
                    }
                    for (; trace_seen != tseq; trace_seen++) {
                        const hh_trace_t &t = w->trace[trace_seen % HH_TRACE_LEN];
                        char hdr[17], head[17];
                        Hex(hdr, t.hdr, sizeof(t.hdr));
                        Hex(head, t.head, sizeof(t.head));
                        Log("trace %u: op=%02x mode=%u rc=%02x st=%02x len=0x%x pend=0x%x hdr=%s head=%s\n",
                            trace_seen, t.op, t.mode, t.rc, t.status, t.len, t.pending, hdr, head);
                    }
                }
                svc::SleepThread(1'000'000);
            }
        }

        /* Reads a one-line config file into dst; empty if missing. */
        void ReadConfigLine(const char *path, char *dst, size_t cap) {
            dst[0] = 0;
            fs::FileHandle f;
            s64 size = 0;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) {
                return;
            }
            if (R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size > 0 && static_cast<size_t>(size) < cap) {
                if (R_SUCCEEDED(fs::ReadFile(f, 0, dst, static_cast<size_t>(size)))) {
                    dst[size] = 0;
                }
            }
            fs::CloseFile(f);
            size_t n = std::strlen(dst);
            while (n > 0 && (dst[n - 1] == '\n' || dst[n - 1] == '\r' || dst[n - 1] == ' ')) {
                dst[--n] = 0;
            }
        }

        void LoadXci() {
            /* boot2 mounts the SD before it launches us; allow for a slow card. */
            Result mount = fs::MountSdCard("sdmc");
            for (int i = 0; R_FAILED(mount) && i < 50; i++) {
                os::SleepThread(TimeSpan::FromMilliSeconds(100));
                mount = fs::MountSdCard("sdmc");
            }
            R_DISCARD(fs::DeleteFile(LogPath));
            R_DISCARD(fs::CreateFile(LogPath, 0));
            Log("xci: sd mount rc=0x%x\n", mount.GetValue());

            char dir[XCI_PATH_MAX];
            ReadConfigLine(LibraryPath, dir, sizeof(dir));
            xci_server_init(std::addressof(g_srv), std::addressof(g_fs), dir[0] ? dir : LibraryDir);

            /* The slot starts empty; the first select inserts a card. */
            xci_server_boot(std::addressof(g_srv), g_window);
            Log("xci: library=%s, slot empty\n", g_srv.dir);
        }

        hh_window_t *MapWindow() {
            for (int i = 0; i < WindowAddressTries; i++) {
                const u64 address = HH_WINDOW_VA - i * WindowAddressStep;
                if (R_SUCCEEDED(svc::MapSharedMemory(g_shmem_handle, svc::Address{address}, WindowSize, svc::MemoryPermission_ReadWrite))) {
                    return reinterpret_cast<hh_window_t *>(address);
                }
            }
            return nullptr;
        }

        int OpSelectPath(const char *path, u32) {
            return xci_server_select(std::addressof(g_srv), g_window, path);
        }

        int OpSelectIndex(const char *, u32 index) {
            return xci_server_select_index(std::addressof(g_srv), g_window, index);
        }

    }

    Result ListImages(u32 *out_total, XciImageEntry *out, size_t count) {
        static xci_catalog_t cat;
        std::scoped_lock lk(g_lock);
        R_TRY(ToResult(xci_catalog_scan(g_srv.fs, g_srv.dir, std::addressof(cat))));
        xci_server_mark_current(std::addressof(g_srv), std::addressof(cat));
        *out_total = cat.count;
        std::memcpy(out, cat.entries, std::min<size_t>(count, cat.count) * sizeof(*out));
        R_SUCCEED();
    }

    void GetStatus(XciStatus *out) {
        const hh_window_t *w = g_window;
        *out = {};
        out->stage = w->stage;
        out->swap_req = w->swap_req;
        out->swap_done = w->swap_done;
        out->mount_code = w->mount_code;
        out->exec_count = w->exec_count;
        out->presence_calls = w->presence_calls;
        out->presence_hits = w->presence_hits;
        out->window_requests = g_window_requests.load();
    }

    void GetCurrentImage(XciImageEntry *out) {
        std::scoped_lock lk(g_lock);
        xci_server_current(std::addressof(g_srv), out);
    }

    Result SelectImageByIndex(u32 index) {
        char what[24];
        util::SNPrintf(what, sizeof(what), "index %u", index);
        R_RETURN(Select(what, OpSelectIndex, nullptr, index));
    }

    Result SelectImageByPath(const char *path) {
        R_RETURN(Select(path, OpSelectPath, path, 0));
    }

    void GetLibraryPath(char *out, size_t size) {
        util::Strlcpy(out, g_srv.dir, size);
    }

}

namespace ams {

    constinit u8 g_xci_malloc[1_MB];

    namespace init {

        void InitializeSystemModule() {
            R_ABORT_UNLESS(sm::Initialize());
            fs::InitializeForSystem();
            fs::SetEnabledAutoAbort(false);
            ams::CheckApiVersion();
        }

        void FinalizeSystemModule() { /* ... */ }

        void Startup() {
            init::InitializeAllocator(g_xci_malloc, sizeof(g_xci_malloc));
        }

    }

    void Main() {
        R_ABORT_UNLESS(os::CreateSharedMemory(std::addressof(xci::g_shared_memory), xci::WindowSize, os::MemoryPermission_ReadWrite, os::MemoryPermission_ReadWrite));
        xci::g_shmem_handle = os::GetSharedMemoryHandle(std::addressof(xci::g_shared_memory));
        xci::g_window = xci::MapWindow();
        AMS_ABORT_UNLESS(xci::g_window != nullptr);
        std::memset(xci::g_window, 0, xci::WindowSize);

        xci::LoadXci();

        R_ABORT_UNLESS(os::CreateThread(std::addressof(xci::g_reader), xci::ReaderThread, nullptr, xci::g_reader_stack, sizeof(xci::g_reader_stack), 12, -2));
        os::SetThreadNamePointer(std::addressof(xci::g_reader), "xci-reader");
        os::StartThread(std::addressof(xci::g_reader));

        R_ABORT_UNLESS(xci::g_server_manager.RegisterObjectForServer(xci::g_service_object.GetShared(), sm::ServiceName::Encode(XCI_SERVICE_NAME), xci::NumSessions));
        xci::g_server_manager.LoopProcess();
    }

}
