/* xci_lib.c - see xci_lib.h. */
#include "xci_lib.h"

#include <string.h>

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static const char *last_component(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* dst = a + b, bounded. */
static bool join(char *dst, size_t cap, const char *a, const char *b)
{
    size_t na = strlen(a), nb = strlen(b);
    if (na + nb + 1 > cap)
        return false;
    memcpy(dst, a, na);
    memcpy(dst + na, b, nb + 1);
    return true;
}

int xci_resolve(const char *dir, const char *in, xci_ref_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!in || !in[0] || strstr(in, "..") || ends_with(in, "/"))
        return XciError_InvalidPath;
    if (strncmp(in, "sdmc:/", 6) == 0) {
        if (strlen(in) + 1 > sizeof(out->path))
            return XciError_InvalidPath;
        memcpy(out->path, in, strlen(in) + 1);
    } else {
        /* Names live directly in the library directory. */
        if (strchr(in, '/') || strchr(in, ':'))
            return XciError_InvalidPath;
        if (!join(out->path, sizeof(out->path), dir, in))
            return XciError_InvalidPath;
    }
    if (ends_with(out->path, ".xci")) {
        out->split = false;
    } else {
        /* Split pair: "name", "name.xc0" or "name.xc1" all mean name.xc0+.xc1. */
        if (ends_with(out->path, ".xc0") || ends_with(out->path, ".xc1"))
            out->path[strlen(out->path) - 4] = 0;
        out->split = true;
    }
    const char *name = last_component(out->path);
    if (!name[0] || strlen(name) + 1 > XCI_NAME_MAX)
        return XciError_InvalidPath;
    return 0;
}

typedef struct {
    XciImageEntry e;
    bool has0;
} scan_item_t;

typedef struct {
    scan_item_t items[XCI_MAX_IMAGES];
    uint32_t count;
} scan_t;

static scan_item_t *scan_find(scan_t *sc, const char *name)
{
    for (uint32_t i = 0; i < sc->count; i++)
        if (strcmp(sc->items[i].e.name, name) == 0)
            return &sc->items[i];
    if (sc->count == XCI_MAX_IMAGES)
        return NULL;
    scan_item_t *it = &sc->items[sc->count++];
    memset(it, 0, sizeof(*it));
    memcpy(it->e.name, name, strlen(name) + 1);
    return it;
}

static void scan_add(void *cookie, const char *file, uint64_t size)
{
    scan_t *sc = (scan_t *)cookie;
    size_t n = strlen(file);
    /* Dot files are hidden; macOS leaves "._name.xci" AppleDouble files
     * beside every image it copies. */
    if (file[0] == '.' || n < 5 || n + 1 > XCI_NAME_MAX)
        return;
    char base[XCI_NAME_MAX];
    if (ends_with(file, ".xci")) {
        scan_item_t *it = scan_find(sc, file);
        if (it) {
            it->e.size = size;
            it->e.parts = 1;
            it->has0 = true;
        }
    } else if (ends_with(file, ".xc0") || ends_with(file, ".xc1")) {
        memcpy(base, file, n - 4);
        base[n - 4] = 0;
        scan_item_t *it = scan_find(sc, base);
        if (it) {
            it->e.size += size;
            it->e.parts++;
            if (file[n - 1] == '0')
                it->has0 = true;
        }
    }
}

int xci_catalog_scan(const xci_fs_t *fs, const char *dir, xci_catalog_t *cat)
{
    static scan_t sc; /* 64 entries: keep it off small sysmodule stacks */
    memset(cat, 0, sizeof(*cat));
    memset(&sc, 0, sizeof(sc));
    if (fs->list(fs->ctx, dir, scan_add, &sc) != 0)
        return XciError_ListFailed;
    /* A lone .xc1 is not an image. */
    for (uint32_t i = 0; i < sc.count; i++)
        if (sc.items[i].has0)
            cat->entries[cat->count++] = sc.items[i].e;
    for (uint32_t i = 1; i < cat->count; i++) {
        XciImageEntry e = cat->entries[i];
        uint32_t j = i;
        for (; j > 0 && strcmp(cat->entries[j - 1].name, e.name) > 0; j--)
            cat->entries[j] = cat->entries[j - 1];
        cat->entries[j] = e;
    }
    return 0;
}

int xci_image_open(const xci_fs_t *fs, const xci_ref_t *ref, xci_image_t *img)
{
    memset(img, 0, sizeof(*img));
    img->ref = *ref;
    const char *name = last_component(ref->path);
    memcpy(img->name, name, strlen(name) + 1);

    char path[XCI_PATH_MAX + 4];
    uint64_t size1 = 0;
    if (!ref->split) {
        if (fs->open(fs->ctx, ref->path, &img->part0, &img->size0) != 0)
            return XciError_OpenFailed;
    } else {
        join(path, sizeof(path), ref->path, ".xc0");
        if (fs->open(fs->ctx, path, &img->part0, &img->size0) != 0)
            return XciError_OpenFailed;
        join(path, sizeof(path), ref->path, ".xc1");
        if (fs->open(fs->ctx, path, &img->part1, &size1) != 0)
            img->part1 = NULL;
    }
    img->total = img->size0 + size1;
    img->open = true;

    /* Card header: "HEAD" at 0x100, or at 0x1100 behind a CardKeyArea. */
    uint8_t hdr[0x104];
    bool ok = (xci_image_read(fs, img, 0, hdr, sizeof(hdr)) == 0 &&
               memcmp(hdr + 0x100, "HEAD", 4) == 0) ||
              (xci_image_read(fs, img, 0x1000, hdr, sizeof(hdr)) == 0 &&
               memcmp(hdr + 0x100, "HEAD", 4) == 0);
    if (!ok) {
        xci_image_close(fs, img);
        return XciError_NotAnImage;
    }
    return 0;
}

void xci_image_close(const xci_fs_t *fs, xci_image_t *img)
{
    if (img->part0)
        fs->close(fs->ctx, img->part0);
    if (img->part1)
        fs->close(fs->ctx, img->part1);
    memset(img, 0, sizeof(*img));
}

int xci_image_read(const xci_fs_t *fs, const xci_image_t *img, uint64_t off, void *buf, size_t n)
{
    if (!img->open || off > img->total || n > img->total - off)
        return -1;
    uint8_t *dst = (uint8_t *)buf;
    if (off < img->size0) {
        size_t first = n;
        if (first > img->size0 - off)
            first = (size_t)(img->size0 - off);
        int rc = fs->read(fs->ctx, img->part0, off, dst, first);
        if (rc != 0)
            return rc;
        dst += first;
        off += first;
        n -= first;
    }
    if (n > 0) {
        if (!img->part1)
            return -1;
        return fs->read(fs->ctx, img->part1, off - img->size0, dst, n);
    }
    return 0;
}

void xci_server_init(xci_server_t *s, const xci_fs_t *fs, const char *dir)
{
    memset(s, 0, sizeof(*s));
    s->fs = fs;
    size_t n = strlen(dir);
    if (n + 2 > sizeof(s->dir))
        n = sizeof(s->dir) - 2;
    memcpy(s->dir, dir, n);
    if (n == 0 || s->dir[n - 1] != '/')
        s->dir[n++] = '/';
    s->dir[n] = 0;
}

void xci_server_boot(xci_server_t *s, hh_window_t *w)
{
    w->total = 0;
    s->gen = w->swap_req;
}

int xci_server_select(xci_server_t *s, hh_window_t *w, const char *name_or_path)
{
    if (__atomic_load_n(&w->swap_req, __ATOMIC_ACQUIRE) !=
        __atomic_load_n(&w->swap_done, __ATOMIC_ACQUIRE))
        return XciError_Busy;
    xci_ref_t ref;
    int rc = xci_resolve(s->dir, name_or_path, &ref);
    if (rc != 0)
        return rc;
    xci_image_t img;
    rc = xci_image_open(s->fs, &ref, &img);
    if (rc != 0)
        return rc;
    s->staged = img;
    s->gen++;
    __atomic_store_n(&w->swap_req, s->gen, __ATOMIC_RELEASE);
    return 0;
}

int xci_server_select_index(xci_server_t *s, hh_window_t *w, uint32_t index)
{
    static xci_catalog_t cat;
    int rc = xci_catalog_scan(s->fs, s->dir, &cat);
    if (rc != 0)
        return rc;
    if (index >= cat.count)
        return XciError_InvalidIndex;
    return xci_server_select(s, w, cat.entries[index].name);
}

static bool serve_pages(xci_server_t *s, hh_window_t *w, uint32_t page, uint32_t count)
{
    if (count == 0 || count > HH_WINDOW_DATA_SIZE / HH_WINDOW_PAGE_SIZE)
        return false;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t off = (uint64_t)(page + i) * HH_WINDOW_PAGE_SIZE;
        uint8_t *dst = w->data + (size_t)i * HH_WINDOW_PAGE_SIZE;
        if (off >= s->cur.total)
            return false;
        size_t n = HH_WINDOW_PAGE_SIZE;
        if (n > s->cur.total - off)
            n = (size_t)(s->cur.total - off);
        memset(dst, 0, HH_WINDOW_PAGE_SIZE);
        int rc = xci_image_read(s->fs, &s->cur, off, dst, n);
        if (rc != 0) {
            s->read_failures++;
            s->read_error = rc;
            return false;
        }
    }
    return true;
}

bool xci_server_step(xci_server_t *s, hh_window_t *w)
{
    bool did = false;
    uint32_t req = __atomic_load_n(&w->req, __ATOMIC_ACQUIRE);
    if (req != s->served) {
        bool ok = serve_pages(s, w, w->card_page, w->count);
        s->served = req;
        __atomic_store_n(&w->status, ok ? req : (req | HH_WINDOW_ERROR), __ATOMIC_RELEASE);
        did = true;
    }
    /* The hook acknowledged the removal: no read of the old image remains. */
    uint32_t sreq = __atomic_load_n(&w->swap_req, __ATOMIC_ACQUIRE);
    if (sreq != __atomic_load_n(&w->swap_done, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&w->swap_ack, __ATOMIC_ACQUIRE) == sreq) {
        xci_image_close(s->fs, &s->cur);
        s->cur = s->staged;
        memset(&s->staged, 0, sizeof(s->staged));
        w->total = s->cur.total;
        __atomic_store_n(&w->swap_done, sreq, __ATOMIC_RELEASE);
        did = true;
    }
    return did;
}

static const xci_image_t *target(const xci_server_t *s)
{
    return s->staged.open ? &s->staged : &s->cur;
}

void xci_server_mark_current(const xci_server_t *s, xci_catalog_t *cat)
{
    const xci_image_t *t = target(s);
    char path[XCI_PATH_MAX + XCI_NAME_MAX];
    for (uint32_t i = 0; i < cat->count; i++) {
        XciImageEntry *e = &cat->entries[i];
        e->flags &= ~XCI_IMAGE_FLAG_CURRENT;
        if (!t->open || !join(path, sizeof(path), s->dir, e->name))
            continue;
        /* Split entries are named by their base, like ref.path. */
        if (strcmp(path, t->ref.path) == 0)
            e->flags |= XCI_IMAGE_FLAG_CURRENT;
    }
}

void xci_server_current(const xci_server_t *s, XciImageEntry *out)
{
    const xci_image_t *t = target(s);
    memset(out, 0, sizeof(*out));
    if (!t->open)
        return;
    memcpy(out->name, t->name, sizeof(out->name));
    out->size = t->total;
    out->parts = t->part1 ? 2 : 1;
    out->flags = XCI_IMAGE_FLAG_CURRENT;
}
