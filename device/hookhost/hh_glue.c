/* hh_glue.c - C side of the two detours plus the mount state.
 *
 * The loader calls hh_init(), hh_attach() with the XCI's extent image and
 * hh_set_cert() with a genuine ASIC certificate, then installs the patches
 * with hh_install(). FS calls hh_exec_c / hh_presence_c through hh_tramp.S.
 */
#include "hh.h"
#include "asic.h"
#include "mount.h"
#include "hh_swap.h"

hh_runtime_t hh_runtime;

static gc_asic_t g_asic;
static gc_mount_t g_mount;
static gc_image_t g_img;
static bool g_ready;

static hh_window_t *g_window;
static hh_swap_t g_swap; /* attach/detach and FS's inserted predicate */
/* FS image base from the crt0 return address, plus where this FS build has
 * its code and its bss objects. Zero until the build is identified. */
static uintptr_t g_fs_code;
static uintptr_t g_fs_bss;

/* Window ABI shared with the sysmodule. device/xci/source/xci_main.cpp
 * asserts the same offsets, so a header change that is not rebuilt into both
 * halves fails to compile instead of silently logging garbage. */
_Static_assert(offsetof(hh_window_t, total) == 0x10, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, data) == 0x18, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, stage) == 0x20018, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, exec_count) == 0x20024, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, exec_last) == 0x20028, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, trace_seq) == 0x2002C, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, trace) == 0x20030, "hh_window_t ABI");
_Static_assert(sizeof(hh_trace_t) == 28, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, swap_req) == 0x20730, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, swap_ack) == 0x20734, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, swap_done) == 0x20738, "hh_window_t ABI");
_Static_assert(offsetof(hh_window_t, mount_code) == 0x2073C, "hh_window_t ABI");
_Static_assert(sizeof(hh_window_t) == 0x20740, "hh_window_t ABI");
_Static_assert(sizeof(hh_window_t) <= HH_WINDOW_SIZE, "hh_window_t ABI");

/* Diagnostics, mirrored into the window once it is mapped. nn.gc runs the
 * ASIC bring-up (ops 1-9) before the window exists, so they are kept here. */
static uint32_t g_presence_calls;
static uint32_t g_presence_hits;
static uint32_t g_exec_count;
static uint32_t g_exec_last;
static hh_trace_t g_trace[HH_TRACE_LEN];
static uint32_t g_trace_seq;

static int embedded_read(void *ctx, void *buf, uint64_t sector, uint32_t count)
{
    (void)ctx;
    uint64_t off = sector << GC_SECTOR_SHIFT;
    size_t n = (size_t)count << GC_SECTOR_SHIFT;
    if (off > hh_runtime.xci_size || n > hh_runtime.xci_size - off)
        return -1;
    memcpy(buf, (const void *)(uintptr_t)(hh_runtime.xci_addr + off), n);
    return 0;
}

static void mount_static(void)
{
    if (hh_runtime.path[0]) {
        size_t n = strlen(hh_runtime.path);
        if (n >= sizeof(g_mount.path)) {
            n = sizeof(g_mount.path) - 1;
        }
        memcpy(g_mount.path, hh_runtime.path, n);
        g_mount.path[n] = 0;
        g_mount.status = GC_MOUNT_MOUNTED;
    }
    if (hh_runtime.xci_addr && hh_runtime.xci_size) {
        gc_bdev_t dev = { embedded_read, NULL };
        gc_run_t run = { 0, (hh_runtime.xci_size + GC_SECTOR_SIZE - 1) / GC_SECTOR_SIZE };
        if (gc_image_init(&g_img, &dev, &run, 1, hh_runtime.xci_size) == 0)
            gc_asic_attach(&g_asic, &g_img);
    }
}

/* Offsets into the FS image, as in the FAT32 build of 23.5.0. KIP code is
 * 2 MiB aligned and crt0 sits at its start, so the crt0 return address gives
 * the image base. The exFAT build has the same code and objects further on. */
#define FS_ALIGN_MASK      0x1FFFFFu
static const struct {
    uint32_t code, bss;
} FS_BUILDS[] = {
    { 0, 0 },           /* FAT32 */
    { 0xB200, 0x11000 } /* exFAT */
};
#define FS_SIGNAL_EVENT    0x1A7830u    /* nn::os::SignalEvent(EventType *) */
#define FS_DETECTOR        0xFE9000u    /* nn.gc.DeviceDetector singleton */
#define FS_DETECTOR_GUARD  0xFEE000u    /* its static-init guard byte */
#define FS_DETECTOR_RESCAN 0x308u       /* detector event that forces a re-sample */
#define FS_EVENT_STATE     19u          /* EventType state byte; 1 = initialized */

/* The detector thread samples the inserted predicate once, 128 ms after it
 * starts or after one of its events fires, then blocks. Signalling its rescan
 * event makes it sample again. The caller needs an nnSdk lock tag: an FS
 * thread or the window thread. Returns the HH_STAGE_WAKE_* reached. */
static uint32_t wake_detector(void)
{
    uintptr_t code = __atomic_load_n(&g_fs_code, __ATOMIC_ACQUIRE);
    uintptr_t bss = __atomic_load_n(&g_fs_bss, __ATOMIC_ACQUIRE);
    if (code == 0)
        return HH_STAGE_WAKE_NO_FS;
    if (!(*(const uint8_t *)(bss + FS_DETECTOR_GUARD) & 1))
        return HH_STAGE_WAKE_NO_DETECTOR;
    uint8_t *event = (uint8_t *)(bss + FS_DETECTOR + FS_DETECTOR_RESCAN);
    if (event[FS_EVENT_STATE] != 1)
        return HH_STAGE_WAKE_NO_EVENT;
    ((void (*)(void *))(code + FS_SIGNAL_EVENT))(event);
    return HH_STAGE_WAKE_SENT;
}

static uint64_t g_rng = 0x243F6A8885A308D3ULL;

__attribute__((weak)) void hh_platform_random(void *buf, size_t len)
{
    /* Scaffold splitmix64; the loader must supply randomGet(). */
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        g_rng += 0x9E3779B97F4A7C15ULL;
        uint64_t z = g_rng;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z ^= z >> 31;
        p[i] = (uint8_t)z;
    }
}

static void rng_cb(void *ctx, void *buf, size_t len)
{
    (void)ctx;
    hh_platform_random(buf, len);
}

/* Copies the exec counters and the op trace into the window. */
static void mirror_exec(hh_window_t *w)
{
    w->exec_count = __atomic_load_n(&g_exec_count, __ATOMIC_RELAXED);
    w->exec_last = g_exec_last;
    uint32_t tseq = __atomic_load_n(&g_trace_seq, __ATOMIC_ACQUIRE);
    if (w->trace_seq != tseq) {
        memcpy(w->trace, g_trace, sizeof(g_trace));
        __atomic_store_n(&w->trace_seq, tseq, __ATOMIC_RELEASE);
    }
}

static void trace_op(const uint8_t *hdr, uint8_t mode, int rc, const uint32_t *status,
                     const void *payload, size_t len)
{
    uint32_t n = __atomic_load_n(&g_trace_seq, __ATOMIC_RELAXED);
    hh_trace_t *t = &g_trace[n % HH_TRACE_LEN];
    memset(t, 0, sizeof(*t));
    t->op = hdr[0];
    t->mode = mode;
    t->rc = (uint8_t)rc;
    t->status = status ? (uint8_t)*status : 0xFF;
    t->len = (uint32_t)len;
    t->pending = g_asic.l3.pending_len;
    memcpy(t->hdr, hdr + 1, sizeof(t->hdr));
    if (payload)
        memcpy(t->head, payload, len < sizeof(t->head) ? len : sizeof(t->head));
    __atomic_store_n(&g_trace_seq, n + 1, __ATOMIC_RELEASE);
}

/* Runs on the window thread once the sysmodule's window is mapped. */
static void window_ready(hh_window_t *w)
{
    w->presence_calls = __atomic_load_n(&g_presence_calls, __ATOMIC_RELAXED);
    mirror_exec(w);
    w->stage = HH_STAGE_MAPPED;
    __atomic_store_n(&g_window, w, __ATOMIC_RELEASE);
    hh_swap_boot(&g_swap, w);
}

/* Runs on the window thread every HH_SWAP_POLL_MS after window_ready. */
static void window_poll(hh_window_t *w)
{
    (void)w;
    hh_swap_poll(&g_swap, hh_now_ms());
}

void hh_init(void)
{
#ifdef HH_DIAG_ABORT
    /* Diagnostic: prove the kernel patch reached FS crt0. */
    *(volatile uint32_t *)0xDEAD0000u = 0x12345678u;
#endif
    gc_asic_init(&g_asic, rng_cb, NULL);
    gc_mount_init(&g_mount, NULL, NULL);
    hh_swap_init(&g_swap, &g_asic, &g_img, &g_mount, wake_detector);
    g_ready = true;
    mount_static();
}

int hh_attach(gc_image_t *img)
{
    return g_ready ? gc_asic_attach(&g_asic, img) : -1;
}

void hh_set_cert(const uint8_t *cert, size_t len)
{
    gc_asic_set_cert(&g_asic, cert, len);
}

int hh_mount_request(const char *path, bool physical_present)
{
    return gc_mount_request(&g_mount, path, physical_present);
}

void hh_tick(void)
{
    gc_mount_tick(&g_mount);
}

int hh_status(void)
{
    return gc_mount_code(&g_mount);
}

static void ensure_ready(void)
{
    if (!g_ready)
        hh_init();
}

/* FS decrypts every device -> host frame after the executor returns
 * (sub_18B790), so reads served here are sealed with FS's live session state.
 * GetCardHeader and the CardKeyArea also carry a MAC FS checks (sub_1902C0),
 * keyed with material FS holds. */
#define FS_GC_LINK        0xFEEE80u /* sub_190EC0 object */
#define FS_GC_LINK_SECURE 1u        /* byte: 1 = secure mode, AES-CTR */
#define FS_GC_LINK_KEYED  4u        /* byte: bit 0 = session key set, AES-CBC */
#define FS_GC_SESSION     0xFEEB10u /* sub_18F890 singleton */
#define FS_GC_KEY         0x08u     /* AES-128 key (sub_18FF40) */
#define FS_GC_IV          0x68u     /* CBC IV (sub_18FF40) */
#define FS_GC_CTR         0xE8u     /* pointer to the live CTR counter (sub_190600) */
#define FS_GC_REPLY_CTR   0x1F0u    /* pointer to the reply MAC counter (sub_190270) */
#define FS_GC_MAC_KEY     0xFEE508u /* 32-byte reply HMAC key (off_2579B0) */
#define FS_GC_MAC_SALT    0xFEE538u /* 16-byte reply MAC salt (off_2579C0) */
#define FS_GC_HEADER_KEY  0xFEE560u /* pointer to the CardInfo AES key (sub_18FE60) */

static void finish_read(uint8_t *frame, size_t len, size_t logical)
{
    uintptr_t fs = __atomic_load_n(&g_fs_bss, __ATOMIC_ACQUIRE);
    if (fs == 0)
        return;
    const uint8_t *link = (const uint8_t *)(fs + FS_GC_LINK);
    const uint8_t *session = (const uint8_t *)(fs + FS_GC_SESSION);
    const gc_card_secrets_t secrets = {
        .mac_key = (const uint8_t *)(fs + FS_GC_MAC_KEY),
        .mac_salt = (const uint8_t *)(fs + FS_GC_MAC_SALT),
        .mac_ctr = *(const uint8_t *const *)(session + FS_GC_REPLY_CTR),
        .header_key = *(const uint8_t *const *)(fs + FS_GC_HEADER_KEY),
    };
    if (secrets.mac_ctr != NULL)
        gc_asic_authenticate(&g_asic, frame, len, &secrets);
    if (link[FS_GC_LINK_SECURE] == 1)
        gc_link_seal(GC_LINK_CTR, session + FS_GC_KEY,
                     *(const uint8_t *const *)(session + FS_GC_CTR), frame, len, logical);
    else if (link[FS_GC_LINK_KEYED] & 1)
        gc_link_seal(GC_LINK_CBC, session + FS_GC_KEY, session + FS_GC_IV, frame, len, logical);
}

uint32_t hh_exec_c(void *self, uint32_t *status, void *data, size_t len,
                   void *a4, void *a5, const uint8_t *hdr, uint8_t mode)
{
    (void)self;
    ensure_ready();
    if (!hdr) {
        if (status)
            *status = 1;
        return 1;
    }

    void *payload = (mode == 1) ? a4 : data;
    size_t payload_len = (mode == 1) ? (size_t)(uintptr_t)a5 : len;
    if (!payload) {
        if (status)
            *status = 1;
        trace_op(hdr, mode, 0xFE, status, NULL, 0);
        return 1;
    }
    hh_exec_lock();
    int rc = gc_asic_exec(&g_asic, status, payload, payload_len, hdr);

    __atomic_add_fetch(&g_exec_count, 1, __ATOMIC_RELAXED);
    g_exec_last = hdr[0] | ((uint32_t)rc & 0xFFu) << 8;
    trace_op(hdr, mode, rc, status, payload, payload_len);
    if (mode == 2)
        finish_read((uint8_t *)payload, payload_len, g_asic.l3.pending_len);
    /* The first card command after an insertion completes the mount. */
    hh_swap_note_op(&g_swap, hdr[0], rc);
    hh_exec_unlock();

    hh_window_t *w = __atomic_load_n(&g_window, __ATOMIC_ACQUIRE);
    if (w != NULL)
        mirror_exec(w);
    return (uint32_t)rc;
}

/* Replaces FS's inserted predicate. FS evaluates it while it initialises
 * nn.gc on the first game-card request of the boot, so it only reads and
 * writes memory: anything that faults or blocks here stalls the boot. */
uint32_t hh_presence_c(void *self)
{
    (void)self;
    ensure_ready();
    bool armed = __atomic_load_n(&g_swap.present, __ATOMIC_ACQUIRE);
    uint32_t calls = __atomic_add_fetch(&g_presence_calls, 1, __ATOMIC_RELAXED);
    hh_window_t *w = __atomic_load_n(&g_window, __ATOMIC_ACQUIRE);
    if (w != NULL) {
        w->presence_calls = calls;
        if (armed)
            w->presence_hits = __atomic_add_fetch(&g_presence_hits, 1, __ATOMIC_RELAXED);
    }
    return armed;
}

/* Called once from FS crt0 with the return address into it. Arming never
 * depends on FS asking: the window thread starts here and waits on its own
 * for sm, the sysmodule and the settle delay. */
void hh_entry_c(uintptr_t lr)
{
    hh_init();
    static const uint32_t signal_event[] = {
        0xA9BE7BFDu, 0xA9014FF4u, 0x910003FDu, 0xAA0003F3u, 0x91007000u,
    };
    uintptr_t base = lr & ~(uintptr_t)FS_ALIGN_MASK;
    for (size_t i = 0; i < sizeof(FS_BUILDS) / sizeof(FS_BUILDS[0]); i++) {
        uintptr_t code = base + FS_BUILDS[i].code;
        if (memcmp((const void *)(code + FS_SIGNAL_EVENT), signal_event, sizeof(signal_event)) == 0) {
            g_fs_bss = base + FS_BUILDS[i].bss;
            g_fs_code = code;
            break;
        }
    }
    hh_window_start(window_ready, window_poll);
}
