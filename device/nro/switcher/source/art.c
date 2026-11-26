/* art.c - see art.h. */
#include "art.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <switch.h>
#include <SDL_image.h>

#include "image.h"
#include "nca.h"
#include "xci.h"

static SDL_Surface *try_image(const char *dir, const char *base, const char *ext)
{
    char path[0x400];
    snprintf(path, sizeof(path), "%s%s%s", dir, base, ext);
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0)
        return NULL;
    return IMG_Load(path);
}

SDL_Surface *art_load(const char *library, const char *base)
{
    SDL_Surface *s = try_image(library, base, ".jpg");
    if (!s)
        s = try_image(library, base, ".png");
    if (!s)
        s = try_image(ART_CACHE, base, ".jpg");
    return s;
}

bool art_load_title(const char *base, char *out, size_t n)
{
    char path[0x400];
    snprintf(path, sizeof(path), "%s%s.txt", ART_CACHE, base);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t got = fread(out, 1, n - 1, f);
    fclose(f);
    out[got] = 0;
    while (got > 0 && (out[got - 1] == '\n' || out[got - 1] == '\r'))
        out[--got] = 0;
    return got > 0;
}

static bool write_file(const char *path, const void *data, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const bool ok = fwrite(data, 1, size, f) == size;
    fclose(f);
    return ok;
}

/* The image's parts as one block device (512-byte sectors). */
typedef struct {
    FILE *f[2];
    u64 size[2];
} parts_t;

static int parts_read(void *ctx, void *buf, uint64_t sector, uint32_t count)
{
    parts_t *p = ctx;
    u64 off = sector * GC_SECTOR_SIZE, n = (u64)count * GC_SECTOR_SIZE;
    u8 *b = buf;
    while (n > 0) {
        if (off >= p->size[0] + p->size[1]) { /* the rounded-up last sector */
            memset(b, 0, (size_t)n);
            break;
        }
        const int i = off >= p->size[0];
        const u64 at = i ? off - p->size[0] : off;
        if (!p->f[i] || at >= p->size[i])
            return -1;
        u64 take = p->size[i] - at;
        if (take > n)
            take = n;
        if (fseeko(p->f[i], (off_t)at, SEEK_SET) != 0)
            return -1;
        if (fread(b, 1, (size_t)take, p->f[i]) != take)
            return -1;
        b += take;
        off += take;
        n -= take;
    }
    return 0;
}

static FILE *open_part(const char *library, const char *name, const char *ext, u64 *size)
{
    char path[0x400];
    snprintf(path, sizeof(path), "%s%s%s", library, name, ext);
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size <= 0) {
        fclose(f);
        return NULL;
    }
    *size = (u64)st.st_size;
    return f;
}

#define ICON_MAX 0x20000

int art_extract(keys_t *keys, const char *library, const XciImageEntry *e, const char *base)
{
    const size_t len = strnlen(e->name, sizeof(e->name));
    parts_t p = { { NULL, NULL }, { 0, 0 } };
    if (len > 4 && memcmp(e->name + len - 4, ".xci", 4) == 0) {
        p.f[0] = open_part(library, e->name, "", &p.size[0]);
    } else {
        p.f[0] = open_part(library, e->name, ".xc0", &p.size[0]);
        if (e->parts > 1)
            p.f[1] = open_part(library, e->name, ".xc1", &p.size[1]);
    }
    int rc = GC_NCA_ERR_IO;
    u8 *icon = malloc(ICON_MAX);
    gc_control_t *c = malloc(sizeof(*c));
    if (p.f[0] && (e->parts < 2 || p.f[1]) && icon && c) {
        gc_bdev_t dev = { parts_read, &p };
        const u64 total = p.size[0] + p.size[1];
        gc_run_t run = { 0, (total + GC_SECTOR_SIZE - 1) / GC_SECTOR_SIZE };
        gc_image_t img;
        gc_xci_t x;
        if (gc_image_init(&img, &dev, &run, 1, total) == 0 && gc_xci_open(&x, &img) == 0)
            rc = gc_xci_read_control(&x, &keys->nca, c, icon, ICON_MAX);
        else
            rc = GC_NCA_ERR_FORMAT;
    }
    for (int i = 0; i < 2; i++)
        if (p.f[i])
            fclose(p.f[i]);

    if (rc == 0) {
        mkdir("sdmc:/switch/CardLoader", 0777);
        mkdir(ART_CACHE, 0777);
        char path[0x400];
        snprintf(path, sizeof(path), "%s%s.jpg", ART_CACHE, base);
        if (!write_file(path, icon, c->icon_size))
            rc = GC_NCA_ERR_IO;
        if (c->title[0]) {
            snprintf(path, sizeof(path), "%s%s.txt", ART_CACHE, base);
            write_file(path, c->title, strlen(c->title));
        }
    }
    free(icon);
    free(c);
    return rc;
}
