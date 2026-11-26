/* hh_swap.c - see hh_swap.h. */
#include "hh_swap.h"

#include <string.h>

/* The sysmodule's reader polls every 1 ms; give up after ~5 s of silence. */
#define HH_WINDOW_WAIT_STEPS 50000u

int hh_window_read(hh_window_t *w, void *buf, uint64_t off, size_t n)
{
    uint8_t *dst = (uint8_t *)buf;
    while (n > 0) {
        /* Up to a full window (32 pages) per request: FS reads partition
         * headers of tens of KiB in one ASIC op. */
        uint32_t page = (uint32_t)(off >> 12);
        size_t po = (size_t)(off & (HH_WINDOW_PAGE_SIZE - 1));
        size_t chunk = HH_WINDOW_DATA_SIZE - po;
        if (chunk > n)
            chunk = n;
        uint32_t pages = (uint32_t)((po + chunk + HH_WINDOW_PAGE_SIZE - 1) / HH_WINDOW_PAGE_SIZE);

        uint32_t req = __atomic_load_n(&w->req, __ATOMIC_RELAXED) + 1;
        w->card_page = page;
        w->count = pages;
        __atomic_store_n(&w->req, req, __ATOMIC_RELEASE);

        /* Sleep between polls: a spinning FS thread outranks the reader. */
        uint32_t st;
        uint32_t steps = 0;
        while (((st = __atomic_load_n(&w->status, __ATOMIC_ACQUIRE)) & ~HH_WINDOW_ERROR) != req) {
            if (++steps > HH_WINDOW_WAIT_STEPS)
                return -1;
            hh_window_pause();
        }
        if (st & HH_WINDOW_ERROR)
            return -1;

        memcpy(dst, w->data + po, chunk);
        dst += chunk;
        off += chunk;
        n -= chunk;
    }
    return 0;
}

static int window_bdev_read(void *ctx, void *buf, uint64_t sector, uint32_t count)
{
    return hh_window_read((hh_window_t *)ctx, buf, sector << GC_SECTOR_SHIFT,
                          (size_t)count << GC_SECTOR_SHIFT);
}

static uint32_t g_exec_lock;

void hh_exec_lock(void)
{
    while (__atomic_exchange_n(&g_exec_lock, 1u, __ATOMIC_ACQUIRE))
        hh_window_pause();
}

void hh_exec_unlock(void)
{
    __atomic_store_n(&g_exec_lock, 0u, __ATOMIC_RELEASE);
}

static void swap_pulse(void *ctx)
{
    hh_swap_t *s = (hh_swap_t *)ctx;
    s->last_wake = s->wake ? s->wake() : HH_STAGE_WAKE_NO_FS;
}

static void update_present(hh_swap_t *s)
{
    bool p = s->attached && gc_card_present(s->mount, false);
    __atomic_store_n(&s->present, p, __ATOMIC_RELEASE);
    if (s->w)
        s->w->mount_code = gc_mount_code(s->mount);
}

void hh_swap_init(hh_swap_t *s, gc_asic_t *asic, gc_image_t *img, gc_mount_t *mount,
                  uint32_t (*wake)(void))
{
    memset(s, 0, sizeof(*s));
    s->asic = asic;
    s->img = img;
    s->mount = mount;
    s->wake = wake;
    mount->pulse = swap_pulse;
    mount->pulse_ctx = s;
}

/* Attaches the image the window describes. 1: empty, -1: rejected. */
static int attach_window(hh_swap_t *s)
{
    uint64_t total = s->w->total;
    if (total == 0)
        return 1;
    gc_bdev_t dev = { window_bdev_read, s->w };
    gc_run_t run = { 0, (total + GC_SECTOR_SIZE - 1) / GC_SECTOR_SIZE };
    hh_exec_lock();
    int rc = gc_image_init(s->img, &dev, &run, 1, total) != 0 ||
             gc_asic_attach(s->asic, s->img) != 0 ? -1 : 0;
    s->attached = rc == 0;
    hh_exec_unlock();
    return rc;
}

static void set_mounted(gc_mount_t *m)
{
    memcpy(m->path, "window", sizeof("window"));
    m->status = GC_MOUNT_MOUNTED;
    m->countdown = 0;
}

uint32_t hh_swap_boot(hh_swap_t *s, hh_window_t *w)
{
    s->w = w;
    /* A request staged before the window was mapped is already applied to
     * w->total by the sysmodule. */
    s->target = __atomic_load_n(&w->swap_req, __ATOMIC_ACQUIRE);
    w->swap_ack = s->target;
    int rc = attach_window(s);
    if (rc != 0) {
        update_present(s);
        w->stage = rc > 0 ? HH_STAGE_EMPTY : HH_STAGE_ATTACH_FAILED;
        return w->stage;
    }
    set_mounted(s->mount);
    update_present(s);
    w->stage = HH_STAGE_ARMED;
    swap_pulse(s);
    w->stage = s->last_wake;
    return w->stage;
}

void hh_swap_poll(hh_swap_t *s, uint32_t now_ms)
{
    hh_window_t *w = s->w;
    if (!w)
        return;
    switch (s->state) {
    case HH_SWAP_IDLE: {
        uint32_t req = __atomic_load_n(&w->swap_req, __ATOMIC_ACQUIRE);
        if (req == w->swap_ack)
            break;
        s->target = req;
        s->t0 = now_ms;
        s->calls0 = w->presence_calls;
        /* Removal: the countdown makes the predicate false, the pulse makes
         * the detector remove the card now and re-sample 128 ms later. The
         * predicate goes false before the pulse. */
        __atomic_store_n(&s->present, false, __ATOMIC_RELEASE);
        w->stage = HH_STAGE_SWAP_REMOVING;
        gc_mount_request(s->mount, "window", false);
        update_present(s);
        s->state = HH_SWAP_REMOVING;
        break;
    }
    case HH_SWAP_REMOVING: {
        uint32_t elapsed = now_ms - s->t0;
        bool sampled = w->presence_calls != s->calls0;
        if (!((sampled && elapsed >= HH_SWAP_SETTLE_MS) || elapsed >= HH_SWAP_REMOVE_MAX_MS))
            break;
        /* No ASIC op is in flight once the lock is ours; ops that FS still
         * issues fail like on a pulled card. */
        hh_exec_lock();
        gc_asic_detach(s->asic);
        s->attached = false;
        hh_exec_unlock();
        update_present(s);
        w->stage = HH_STAGE_SWAP_DETACHED;
        __atomic_store_n(&w->swap_ack, s->target, __ATOMIC_RELEASE);
        s->t0 = now_ms;
        s->state = HH_SWAP_DETACHED;
        break;
    }
    case HH_SWAP_DETACHED: {
        if (__atomic_load_n(&w->swap_done, __ATOMIC_ACQUIRE) != s->target) {
            if (now_ms - s->t0 >= HH_SWAP_DONE_MAX_MS)
                w->stage = HH_STAGE_SWAP_TIMEOUT; /* keep waiting, card stays out */
            break;
        }
        int rc = attach_window(s);
        if (rc != 0) {
            s->mount->path[0] = 0;
            s->mount->status = GC_MOUNT_IDLE;
            update_present(s);
            w->stage = rc > 0 ? HH_STAGE_SWAP_EMPTY : HH_STAGE_SWAP_FAILED;
            s->state = HH_SWAP_IDLE;
            break;
        }
        update_present(s);
        w->stage = HH_STAGE_SWAP_INSERTING;
        s->state = HH_SWAP_INSERTING;
        break;
    }
    case HH_SWAP_INSERTING:
        /* gc_mount's countdown; its last tick emits the insertion pulse, so
         * the predicate turns true just before that tick. */
        if (s->mount->countdown <= 1)
            __atomic_store_n(&s->present, s->attached, __ATOMIC_RELEASE);
        if (gc_mount_tick(s->mount)) {
            update_present(s);
            w->stage = s->last_wake == HH_STAGE_WAKE_SENT ? HH_STAGE_SWAP_INSERTED : s->last_wake;
            s->state = HH_SWAP_IDLE;
        }
        break;
    default:
        s->state = HH_SWAP_IDLE;
        break;
    }
}

void hh_swap_note_op(hh_swap_t *s, uint8_t op, int rc)
{
    gc_mount_t *m = s->mount;
    if (op == 0x10 && m->status == GC_MOUNT_PENDING && m->countdown == 0) {
        gc_mount_result(m, rc == 0);
        if (s->w)
            s->w->mount_code = gc_mount_code(m);
    }
}
