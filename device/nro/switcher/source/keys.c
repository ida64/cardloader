/* keys.c - see keys.h. */
#include "keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FS_PROGRAM_ID 0x0100000000000000ull
#define COPY_MAX      (4u << 20) /* FS 23.5.0's read-only data is 0x69000 */

static void sha256(const void *data, size_t len, uint8_t out[32])
{
    sha256CalculateHash(out, data, len);
}

static int unwrap(void *ctx, uint8_t generation, const uint8_t in[16], uint8_t out[16])
{
    keys_t *k = ctx;
    if (generation >= KEYS_GEN_MAX)
        return -1;
    if (!(k->have_kek & (1u << generation))) {
        if (R_FAILED(splCryptoGenerateAesKek(k->kaek_source, generation, 0, k->sealed_kek[generation])))
            return -1;
        k->have_kek |= 1u << generation;
    }
    return R_SUCCEEDED(splCryptoGenerateAesKey(k->sealed_kek[generation], in, out)) ? 0 : -1;
}

/* FS is an initial process: the kernel starts it from INI1, so pm never
 * tracks it and pm:dmnt GetProcessId answers ProcessNotFound (0x20F). The
 * first event of a debug session is CreateProcess, which carries the program
 * ID, so attach to each initial process until it is FS. Attaching holds the
 * target until its handle is closed; nothing here makes IPC calls meanwhile. */
static Result attach_fs(Handle *out)
{
    u64 min = 0, max = 0;
    Result rc = svcGetSystemInfo(&min, SystemInfoType_InitialProcessIdRange, INVALID_HANDLE,
                                 InitialProcessIdRangeInfo_Minimum);
    if (R_SUCCEEDED(rc))
        rc = svcGetSystemInfo(&max, SystemInfoType_InitialProcessIdRange, INVALID_HANDLE,
                              InitialProcessIdRangeInfo_Maximum);
    if (R_FAILED(rc))
        return rc;
    for (u64 pid = min; pid <= max; pid++) {
        Handle h;
        if (R_FAILED(svcDebugActiveProcess(&h, pid)))
            continue; /* exited (boot) or already being debugged */
        DebugEventInfo ev;
        if (R_SUCCEEDED(svcGetDebugEvent(&ev, h)) && ev.type == DebugEventType_CreateProcess &&
            ev.info.create_process.program_id == FS_PROGRAM_ID) {
            *out = h;
            return 0;
        }
        svcCloseHandle(h);
    }
    return MAKERESULT(Module_Libnx, LibnxError_NotFound);
}

/* Copies FS's read-only (CodeStatic, R--) segments into *out. FS is held
 * only between attach and close, and nothing in between touches files. */
static Result copy_fs_rodata(u8 **out, size_t *len)
{
    u8 *buf = malloc(COPY_MAX);
    if (!buf)
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);

    Handle h;
    Result rc = attach_fs(&h);
    if (R_FAILED(rc)) {
        free(buf);
        return rc;
    }
    size_t total = 0;
    for (u64 addr = 0;;) {
        MemoryInfo mi;
        u32 page;
        if (R_FAILED(svcQueryDebugProcessMemory(&mi, &page, h, addr)))
            break;
        if ((mi.type & 0xFF) == MemType_CodeStatic && mi.perm == Perm_R && mi.size <= COPY_MAX - total &&
            R_SUCCEEDED(svcReadDebugProcessMemory(buf + total, h, mi.addr, mi.size)))
            total += mi.size;
        const u64 next = mi.addr + mi.size;
        if (next <= addr)
            break;
        addr = next;
    }
    svcCloseHandle(h);

    if (total == 0) {
        free(buf);
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }
    *out = buf;
    *len = total;
    return 0;
}

bool keys_init(keys_t *k)
{
    memset(k, 0, sizeof(*k));
    k->nca.unwrap = unwrap;
    k->nca.ctx = k;

    u8 *ro = NULL;
    size_t len = 0;
    Result rc = copy_fs_rodata(&ro, &len);
    if (R_FAILED(rc)) {
        snprintf(k->error, sizeof(k->error), "can't read FS (0x%x)", rc);
        return false;
    }
    gc_key_sources_t src;
    const unsigned found = gc_find_key_sources(ro, len, sha256, &src);
    free(ro);
    if (found != GC_KEYSRC_ALL) {
        snprintf(k->error, sizeof(k->error), "key sources not in FS (%u of 3)", __builtin_popcount(found));
        return false;
    }
    memcpy(k->kaek_source, src.key_area_key_application_source, 16);

    rc = splCryptoInitialize();
    if (R_FAILED(rc)) {
        snprintf(k->error, sizeof(k->error), "spl unavailable (0x%x)", rc);
        return false;
    }
    k->spl_open = true;
    u8 kek[16];
    rc = splCryptoGenerateAesKek(src.header_kek_source, 0, 0, kek);
    if (R_SUCCEEDED(rc))
        rc = splCryptoGenerateAesKey(kek, src.header_key_source, k->nca.header_key);
    if (R_SUCCEEDED(rc))
        rc = splCryptoGenerateAesKey(kek, src.header_key_source + 16, k->nca.header_key + 16);
    if (R_FAILED(rc)) {
        snprintf(k->error, sizeof(k->error), "spl key generation failed (0x%x)", rc);
        keys_exit(k);
        return false;
    }
    return true;
}

void keys_exit(keys_t *k)
{
    if (k->spl_open)
        splCryptoExit();
    k->spl_open = false;
    memset(&k->nca.header_key, 0, sizeof(k->nca.header_key));
    memset(k->sealed_kek, 0, sizeof(k->sealed_kek));
    k->have_kek = 0;
}
