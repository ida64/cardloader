/* Hot swap end to end on the host: the sysmodule half (xci_lib.c) serving a
 * window from in-memory files on its own thread, the hook half (hh_swap.c)
 * driving FS's removal/insertion, and an "FS" thread issuing page reads
 * through gc_asic_exec under the exec lock, as hh_exec_c does. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asic.h"
#include "hh_swap.h"
#include "xci_lib.h"

static int fails;

static void chk(const char *name, int cond)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        fails++;
}

void hh_window_pause(void)
{
    usleep(50);
}

#define DIR "sdmc:/lib/"

typedef struct {
    const char *name;
    uint8_t *data;
    uint64_t size;
    int open;
} memfile_t;

static memfile_t g_files[8];
static int g_nfiles;
static volatile int g_slow_us;     /* delay per read, to keep a transfer in flight */
static volatile int g_reads;

/* Page p of an image holds (tag, p) in every 4-byte word; the card header
 * sits in page 0 with "HEAD" at 0x100 and the tag at 0x10D. */
static uint8_t *make_image(uint64_t size, uint8_t tag)
{
    uint8_t *d = malloc(size);
    for (uint64_t off = 0; off < size; off += 4) {
        uint32_t page = (uint32_t)(off / 0x200);
        d[off] = tag;
        d[off + 1] = (uint8_t)page;
        d[off + 2] = (uint8_t)(page >> 8);
        d[off + 3] = 0x5A;
    }
    memset(d + 0x100, 0, 0x100);
    memcpy(d + 0x100, "HEAD", 4);
    d[0x10D] = tag;
    return d;
}

static void add_file(const char *name, uint8_t *data, uint64_t size)
{
    g_files[g_nfiles++] = (memfile_t){ name, data, size, 0 };
}

static memfile_t *find(const char *path)
{
    if (strncmp(path, DIR, strlen(DIR)) != 0)
        return NULL;
    for (int i = 0; i < g_nfiles; i++)
        if (strcmp(g_files[i].name, path + strlen(DIR)) == 0)
            return &g_files[i];
    return NULL;
}

static int mem_open(void *ctx, const char *path, void **file, uint64_t *size)
{
    (void)ctx;
    memfile_t *f = find(path);
    if (!f)
        return -1;
    f->open++;
    *file = f;
    *size = f->size;
    return 0;
}

static void mem_close(void *ctx, void *file)
{
    (void)ctx;
    ((memfile_t *)file)->open--;
}

static int mem_read(void *ctx, void *file, uint64_t off, void *buf, size_t n)
{
    (void)ctx;
    memfile_t *f = file;
    if (off > f->size || n > f->size - off)
        return -2;
    if (g_slow_us)
        usleep(g_slow_us);
    __atomic_add_fetch(&g_reads, 1, __ATOMIC_RELAXED);
    memcpy(buf, f->data + off, n);
    return 0;
}

static int mem_list(void *ctx, const char *dir, void (*add)(void *, const char *, uint64_t), void *cookie)
{
    (void)ctx;
    if (strcmp(dir, DIR) != 0)
        return -1;
    for (int i = g_nfiles - 1; i >= 0; i--) /* unsorted on purpose */
        add(cookie, g_files[i].name, g_files[i].size);
    return 0;
}

static const xci_fs_t g_fs = { mem_open, mem_close, mem_read, mem_list, NULL };

static hh_window_t *g_w;
static xci_server_t g_srv;
static pthread_mutex_t g_srv_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_stop;

static void *sysmodule_thread(void *arg)
{
    (void)arg;
    while (!g_stop) {
        pthread_mutex_lock(&g_srv_lock);
        xci_server_step(&g_srv, g_w);
        pthread_mutex_unlock(&g_srv_lock);
        usleep(100);
    }
    return NULL;
}

static int ipc_select(const char *name)
{
    pthread_mutex_lock(&g_srv_lock);
    int rc = xci_server_select(&g_srv, g_w, name);
    pthread_mutex_unlock(&g_srv_lock);
    return rc;
}

static int ipc_select_index(uint32_t index)
{
    pthread_mutex_lock(&g_srv_lock);
    int rc = xci_server_select_index(&g_srv, g_w, index);
    pthread_mutex_unlock(&g_srv_lock);
    return rc;
}

static gc_asic_t g_asic;
static gc_image_t g_img;
static gc_mount_t g_mount;
static hh_swap_t g_swap;

/* FS's detector: each wake re-samples the predicate. */
static int g_wakes;
static bool g_wake_saw[8];

static uint32_t wake(void)
{
    if (g_wakes < 8)
        g_wake_saw[g_wakes] = g_swap.present;
    g_wakes++;
    g_w->presence_calls++;
    return HH_STAGE_WAKE_SENT;
}

static void rng(void *ctx, void *out, size_t len)
{
    (void)ctx;
    memset(out, 0x42, len);
}

/* An FS bulk read (op 0x10, byte 1 = 3) under the exec lock, like hh_exec_c. */
static int fs_read_pages(uint32_t page, uint32_t count, uint8_t *buf)
{
    uint8_t hdr[GC_OP_SIZE] = { 0x10, 3 };
    uint32_t st = 0xFFFF;
    gc_wr32(hdr + 4, count);
    hdr[8] = 0x5B;
    gc_wr32be(hdr + 9, page);
    hh_exec_lock();
    int rc = gc_asic_exec(&g_asic, &st, buf, (size_t)count * 0x200, hdr);
    hh_swap_note_op(&g_swap, 0x10, rc);
    hh_exec_unlock();
    return rc == 0 && st == 0 ? 0 : -1;
}

/* Every page holds its own number and the image tag. */
static bool pages_are(const uint8_t *buf, uint32_t page, uint32_t count, uint8_t tag)
{
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = buf + (size_t)i * 0x200;
        uint32_t want = page + i;
        if (want == 0)
            continue; /* page 0 carries the header */
        for (int w = 0; w < 0x200; w += 4)
            if (p[w] != tag || p[w + 1] != (uint8_t)want || p[w + 2] != (uint8_t)(want >> 8))
                return false;
    }
    return true;
}

typedef struct {
    uint32_t page, count;
    uint8_t *buf;
    int rc;
    volatile int done;
} fs_job_t;

static void *fs_thread(void *arg)
{
    fs_job_t *j = arg;
    j->rc = fs_read_pages(j->page, j->count, j->buf);
    j->done = 1;
    return NULL;
}

/* Runs the hook's poll on a simulated 50 ms clock until the swap settles,
 * recording what FS would observe on each step. */
static uint32_t g_now;
static uint32_t g_stages[64];
static int g_nstages;
static bool g_present_during_swap;

static void run_swap(void)
{
    g_nstages = 0;
    g_present_during_swap = false;
    for (int i = 0; i < 400; i++) {
        hh_swap_poll(&g_swap, g_now);
        g_now += HH_SWAP_POLL_MS;
        uint32_t st = g_w->stage;
        if (g_nstages == 0 || g_stages[g_nstages - 1] != st)
            if (g_nstages < 64)
                g_stages[g_nstages++] = st;
        if (g_swap.state != HH_SWAP_IDLE && g_swap.present)
            g_present_during_swap = true;
        if (g_swap.state == HH_SWAP_IDLE && g_w->swap_ack == g_w->swap_req &&
            g_w->swap_done == g_w->swap_req && i > 0)
            break;
        usleep(500);
    }
}

static bool stage_order(const uint32_t *want, int n)
{
    int k = 0;
    for (int i = 0; i < g_nstages && k < n; i++)
        if (g_stages[i] == want[k])
            k++;
    return k == n;
}

int main(void)
{
    uint8_t *alpha = make_image(0x40000, 0xA1);
    uint8_t *beta = make_image(0x30000, 0xB2); /* split at 0x20000 */
    uint8_t *gamma = make_image(0x8000, 0xC3);
    uint8_t *bad = make_image(0x2000, 0xD4);
    memcpy(bad + 0x100, "NOPE", 4);
    add_file("alpha.xci", alpha, 0x40000);
    add_file("beta.xc1", beta + 0x20000, 0x10000);
    add_file("beta.xc0", beta, 0x20000);
    add_file("gamma.xc0", gamma, 0x8000);
    add_file("stray.xc1", gamma, 0x8000);
    add_file("notes.txt", gamma, 0x100);
    add_file("bad.xci", bad, 0x2000);

    // Names and the library listing.
    xci_ref_t ref;
    chk("resolve name.xci", xci_resolve(DIR, "alpha.xci", &ref) == 0 && !ref.split &&
                            strcmp(ref.path, DIR "alpha.xci") == 0);
    chk("resolve split base", xci_resolve(DIR, "beta", &ref) == 0 && ref.split &&
                              strcmp(ref.path, DIR "beta") == 0);
    chk("resolve .xc1 to its pair", xci_resolve(DIR, "beta.xc1", &ref) == 0 && ref.split &&
                                    strcmp(ref.path, DIR "beta") == 0);
    chk("resolve absolute path", xci_resolve(DIR, "sdmc:/lib/alpha.xci", &ref) == 0 &&
                                 strcmp(ref.path, DIR "alpha.xci") == 0);
    chk("reject empty", xci_resolve(DIR, "", &ref) == XciError_InvalidPath);
    chk("reject ..", xci_resolve(DIR, "../x.xci", &ref) == XciError_InvalidPath);
    chk("reject subdir name", xci_resolve(DIR, "sub/x.xci", &ref) == XciError_InvalidPath);

    static xci_catalog_t cat;
    chk("scan", xci_catalog_scan(&g_fs, DIR, &cat) == 0);
    chk("scan: 4 images (lone .xc1 and .txt skipped)", cat.count == 4);
    chk("scan: sorted", cat.count == 4 && strcmp(cat.entries[0].name, "alpha.xci") == 0 &&
                        strcmp(cat.entries[1].name, "bad.xci") == 0 &&
                        strcmp(cat.entries[2].name, "beta") == 0 &&
                        strcmp(cat.entries[3].name, "gamma") == 0);
    chk("scan: split pair has 2 parts and both sizes", cat.entries[2].parts == 2 &&
                                                       cat.entries[2].size == 0x30000);
    chk("scan: .xc0 alone has 1 part", cat.entries[3].parts == 1);
    chk("scan: missing directory fails", xci_catalog_scan(&g_fs, "sdmc:/nope/", &cat) == XciError_ListFailed);

    // Boot: the slot is empty until the first select.
    g_w = calloc(1, sizeof(*g_w));
    xci_server_init(&g_srv, &g_fs, "sdmc:/lib");
    chk("library dir gets a trailing slash", strcmp(g_srv.dir, DIR) == 0);
    xci_server_boot(&g_srv, g_w);
    chk("boot opens no image", g_w->total == 0 && !g_srv.cur.open && g_nfiles > 0 && g_files[0].open == 0);
    pthread_t sys;
    pthread_create(&sys, NULL, sysmodule_thread, NULL);

    gc_asic_init(&g_asic, rng, NULL);
    gc_mount_init(&g_mount, NULL, NULL);
    hh_swap_init(&g_swap, &g_asic, &g_img, &g_mount, wake);
    g_w->stage = HH_STAGE_MAPPED;
    chk("hook boot reports no card", hh_swap_boot(&g_swap, g_w) == HH_STAGE_EMPTY && !g_swap.present);
    for (int i = 0; i < 10; i++)
        hh_swap_poll(&g_swap, g_now += HH_SWAP_POLL_MS);
    chk("no card without a select", !g_swap.present && g_w->stage == HH_STAGE_EMPTY && g_wakes == 0);
    XciImageEntry cur;
    xci_server_current(&g_srv, &cur);
    chk("no current image", cur.name[0] == 0);

    // The first select inserts alpha.
    static uint8_t buf[0x100 * 0x200], buf2[0x20 * 0x200];
    chk("select alpha", ipc_select("alpha.xci") == 0);
    run_swap();
    chk("card present after the first select", g_swap.present && g_w->stage == HH_STAGE_SWAP_INSERTED);
    chk("insertion wake saw the card inserted", g_wakes >= 1 && g_wake_saw[g_wakes - 1]);
    chk("ASIC holds alpha's header", g_asic.l3.xci_header[0x10D] == 0xA1);
    chk("read alpha", fs_read_pages(0x10, 0x20, buf2) == 0 && pages_are(buf2, 0x10, 0x20, 0xA1));
    chk("mount mounted after the first read", g_w->mount_code == GC_STATUS_MOUNTED);

    // Failed selects leave the mounted card alone.
    uint32_t req0 = g_w->swap_req;
    chk("select missing file fails", ipc_select("nope.xci") == XciError_OpenFailed);
    chk("select bad path fails", ipc_select("../alpha.xci") == XciError_InvalidPath);
    chk("select image without header fails", ipc_select("bad.xci") == XciError_NotAnImage);
    chk("select index out of range fails", ipc_select_index(9) == XciError_InvalidIndex);
    chk("no swap started", g_w->swap_req == req0 && g_w->swap_done == req0);
    for (int i = 0; i < 10; i++)
        hh_swap_poll(&g_swap, g_now += HH_SWAP_POLL_MS);
    chk("card still present", g_swap.present && g_w->stage == HH_STAGE_SWAP_INSERTED);
    chk("still reads alpha", fs_read_pages(0x40, 0x20, buf2) == 0 && pages_are(buf2, 0x40, 0x20, 0xA1));
    int open_files = 0;
    for (int i = 0; i < g_nfiles; i++)
        open_files += g_files[i].open;
    chk("failed selects closed what they opened", open_files == 1);

    // Select beta while a 0x100-page read of alpha is in flight.
    g_slow_us = 2000;
    fs_job_t job = { 0x100, 0x100, buf, -1, 0 };
    pthread_t fst;
    int reads0 = g_reads;
    pthread_create(&fst, NULL, fs_thread, &job);
    while (g_reads == reads0)
        usleep(100);
    chk("select beta by index", ipc_select_index(2) == 0);
    chk("second select while swapping is busy", ipc_select("gamma") == XciError_Busy);
    g_wakes = 0;
    run_swap();
    pthread_join(fst, NULL);
    g_slow_us = 0;
    chk("in-flight read completed", job.done && job.rc == 0);
    chk("in-flight read is alpha only", pages_are(buf, 0x100, 0x100, 0xA1));

    const uint32_t order[] = { HH_STAGE_SWAP_REMOVING, HH_STAGE_SWAP_DETACHED,
                               HH_STAGE_SWAP_INSERTING, HH_STAGE_SWAP_INSERTED };
    chk("stages: removing, detached, inserting, inserted", stage_order(order, 4));
    chk("handshake complete", g_w->swap_ack == g_w->swap_req && g_w->swap_done == g_w->swap_req);
    chk("two detector wakes: removal then insertion", g_wakes == 2);
    chk("removal wake saw the card removed", !g_wake_saw[0]);
    chk("insertion wake saw the card inserted", g_wake_saw[1]);
    chk("card reads as removed throughout the swap", !g_present_during_swap);
    chk("card present after the swap", g_swap.present);

    chk("window total is beta's", g_w->total == 0x30000);
    chk("ASIC holds beta's header", g_asic.l3.xci_header[0x10D] == 0xB2);
    chk("mount pending until the first card command", g_w->mount_code == GC_STATUS_PENDING);
    chk("read beta across the .xc0/.xc1 split", fs_read_pages(0xF8, 0x10, buf2) == 0 &&
                                               pages_are(buf2, 0xF8, 0x10, 0xB2));
    chk("mount mounted after it", g_w->mount_code == GC_STATUS_MOUNTED);
    chk("read past beta's end fails", fs_read_pages(0x180, 1, buf2) != 0);
    open_files = 0;
    for (int i = 0; i < g_nfiles; i++)
        open_files += g_files[i].open;
    chk("alpha closed, beta's two parts open", open_files == 2 && g_files[0].open == 0);

    xci_server_current(&g_srv, &cur);
    chk("current is beta", strcmp(cur.name, "beta") == 0 && cur.parts == 2 && cur.size == 0x30000);
    xci_catalog_scan(&g_fs, DIR, &cat);
    xci_server_mark_current(&g_srv, &cat);
    chk("listing marks beta current", cat.entries[2].flags == XCI_IMAGE_FLAG_CURRENT &&
                                      cat.entries[0].flags == 0);

    // And back, by absolute path.
    chk("select alpha by path", ipc_select("sdmc:/lib/alpha.xci") == 0);
    run_swap();
    chk("back on alpha", g_w->total == 0x40000 && g_asic.l3.xci_header[0x10D] == 0xA1 &&
                         fs_read_pages(0x20, 0x20, buf2) == 0 && pages_are(buf2, 0x20, 0x20, 0xA1));

    g_stop = 1;
    pthread_join(sys, NULL);
    if (fails)
        printf("%d failure(s)\n", fails);
    else
        printf("PASS\n");
    return fails ? 1 : 0;
}
