/* FAT12/16/32 + exFAT reader tests.
 *
 * Built-in: synthesises volumes in memory (bare and MBR-partitioned, 512..4096
 * byte sectors, 512 B..128 KiB clusters, fragmented chains, VFAT LFN / exFAT
 * name sets, deleted and corrupt entries, loops) and checks stat/read/runs.
 *
 * Real images: extra arguments are triples  IMAGE  PATH-IN-VOLUME  HOST-FILE;
 * the file in the image must equal HOST-FILE byte for byte. Example recipe
 * (macOS, images kept in /tmp):
 *   dd if=/dev/zero of=/tmp/gcfat/f32.img bs=1m count=0 seek=96
 *   dev=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage \
 *         /tmp/gcfat/f32.img | awk '{print $1}')
 *   newfs_msdos -F 32 -c 8 $dev && hdiutil detach $dev
 *   hdiutil attach -imagekey diskimage-class=CRawDiskImage \
 *         -mountpoint /tmp/gcfat/mnt /tmp/gcfat/f32.img
 *   mkdir "/tmp/gcfat/mnt/Some Dir" && cp payload "/tmp/gcfat/mnt/Some Dir/Long Name.xci"
 *   hdiutil detach /tmp/gcfat/mnt
 *   build/test_fat /tmp/gcfat/f32.img "some dir/long name.XCI" payload
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fat.h"

static int fails;

static void ck(int cond, const char *fmt, ...)
{
    va_list ap;
    printf(cond ? "ok   " : "FAIL ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    if (!cond)
        fails++;
}

typedef struct {
    const uint8_t *p;
    uint64_t size;
    int fail; /* force I/O errors */
} memdev_t;

static int mem_read(void *ctx, void *buf, uint64_t sec, uint32_t cnt)
{
    memdev_t *m = (memdev_t *)ctx;
    uint64_t off = sec * 512, n = (uint64_t)cnt * 512;
    if (m->fail || off > m->size || n > m->size - off)
        return -1;
    memcpy(buf, m->p + off, (size_t)n);
    return 0;
}

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }

static size_t u16s(const char *s, uint16_t *o)
{
    size_t n = 0;
    while (s[n]) {
        o[n] = (uint8_t)s[n];
        n++;
    }
    return n;
}

static uint8_t *pattern(uint64_t size, unsigned seed)
{
    uint8_t *p = malloc(size ? (size_t)size : 1);
    uint32_t x = 0x9E3779B9u ^ seed;
    for (uint64_t i = 0; i < size; i++) {
        x = x * 1664525u + 1013904223u;
        p[i] = (uint8_t)(x >> 24);
    }
    return p;
}

/* expand {start,len} pairs into a cluster list */
static size_t ext_list(uint32_t *out, const uint32_t *pairs, size_t np)
{
    size_t n = 0;
    for (size_t i = 0; i < np; i++)
        for (uint32_t k = 0; k < pairs[2 * i + 1]; k++)
            out[n++] = pairs[2 * i] + k;
    return n;
}

static size_t count_runs(const uint32_t *cl, size_t n)
{
    size_t r = n ? 1 : 0;
    for (size_t i = 1; i < n; i++)
        if (cl[i] != cl[i - 1] + 1)
            r++;
    return r;
}

#define EXF 64

typedef struct {
    uint8_t *img;
    uint64_t size;
    int type; /* 12, 16, 32 or EXF */
    uint64_t vol;
    uint32_t bps, cb, ncl;
    uint64_t fat[2];
    int nfat_write;
    uint64_t heap, root;
} mk_t;

static uint64_t coff(const mk_t *m, uint32_t c) { return m->heap + (uint64_t)(c - 2) * m->cb; }

static uint32_t eoc(const mk_t *m)
{
    return m->type == 12 ? 0xFFF : m->type == 16 ? 0xFFFF : m->type == 32 ? 0x0FFFFFFF : 0xFFFFFFFF;
}

static void set_fat(mk_t *m, uint32_t c, uint32_t v)
{
    for (int k = 0; k < m->nfat_write; k++) {
        uint8_t *f = m->img + m->fat[k];
        if (m->type == 12) {
            uint8_t *p = f + c + c / 2;
            uint32_t w = p[0] | (p[1] << 8);
            w = (c & 1) ? ((w & 0x000F) | (v << 4)) : ((w & 0xF000) | (v & 0xFFF));
            put16(p, w);
        } else if (m->type == 16) {
            put16(f + 2 * c, v);
        } else if (m->type == 32) {
            put32(f + 4 * c, v & 0x0FFFFFFF);
        } else {
            put32(f + 4 * c, v);
        }
    }
}

static void chain(mk_t *m, const uint32_t *cl, size_t n)
{
    for (size_t i = 0; i < n; i++)
        set_fat(m, cl[i], i + 1 < n ? cl[i + 1] : eoc(m));
}

static void write_data(mk_t *m, const uint32_t *cl, size_t n, const uint8_t *d, uint64_t size)
{
    for (size_t i = 0; i < n && (uint64_t)i * m->cb < size; i++) {
        uint64_t take = size - (uint64_t)i * m->cb;
        if (take > m->cb)
            take = m->cb;
        memcpy(m->img + coff(m, cl[i]), d + (uint64_t)i * m->cb, (size_t)take);
    }
}

static void mbr_entry(uint8_t *img, int slot, uint8_t type, uint32_t lba, uint32_t secs)
{
    uint8_t *e = img + 446 + 16 * slot;
    e[4] = type;
    put32(e + 8, lba);
    put32(e + 12, secs);
    img[510] = 0x55;
    img[511] = 0xAA;
}

static void mk_fat(mk_t *m, int type, uint32_t bps, uint32_t spc, uint32_t total, uint32_t root_ents,
                   uint32_t part_lba, int mirror_off)
{
    uint32_t rsvd = type == 32 ? 32 : 1, nf = 2, rs = (root_ents * 32 + bps - 1) / bps;
    uint32_t fatsz = 1, ncl;
    for (;;) {
        ncl = (total - rsvd - nf * fatsz - rs) / spc;
        uint64_t need = type == 12 ? ((uint64_t)(ncl + 2) * 3 + 1) / 2 : (uint64_t)(ncl + 2) * (uint32_t)(type / 8);
        uint32_t f = (uint32_t)((need + bps - 1) / bps);
        if (f <= fatsz)
            break;
        fatsz = f;
    }
    memset(m, 0, sizeof *m);
    m->vol = (uint64_t)part_lba * 512;
    m->size = m->vol + (uint64_t)total * bps;
    m->img = calloc(1, (size_t)m->size);
    if (part_lba) {
        mbr_entry(m->img, 0, 0x83, 1, 1); /* decoy: no FAT volume at LBA 1 */
        mbr_entry(m->img, 1, type == 32 ? 0x0C : type == 16 ? 0x06 : 0x01, part_lba,
                  (uint32_t)((uint64_t)total * bps / 512));
    }
    uint8_t *b = m->img + m->vol;
    b[0] = 0xEB; b[1] = 0x58; b[2] = 0x90;
    memcpy(b + 3, "MSWIN4.1", 8);
    put16(b + 11, bps);
    b[13] = (uint8_t)spc;
    put16(b + 14, rsvd);
    b[16] = (uint8_t)nf;
    put16(b + 17, root_ents);
    if (type != 32 && total < 65536)
        put16(b + 19, total);
    else
        put32(b + 32, total);
    b[21] = 0xF8;
    if (type != 32) {
        put16(b + 22, fatsz);
    } else {
        put32(b + 36, fatsz);
        put16(b + 40, mirror_off ? 0x81 : 0); /* 0x81: only FAT #1 is live */
        put32(b + 44, 2);
    }
    b[510] = 0x55; b[511] = 0xAA;

    m->type = type;
    m->bps = bps;
    m->cb = bps * spc;
    m->ncl = ncl;
    m->fat[0] = m->vol + (uint64_t)rsvd * bps;
    m->fat[1] = m->fat[0] + (uint64_t)fatsz * bps;
    m->nfat_write = 2;
    if (mirror_off) {
        memset(m->img + m->fat[0], 0xA5, (size_t)fatsz * bps); /* stale FAT #0 */
        m->fat[0] = m->fat[1];
        m->nfat_write = 1;
    }
    m->root = m->vol + ((uint64_t)rsvd + (uint64_t)nf * fatsz) * bps;
    m->heap = m->root + (uint64_t)rs * bps;
    set_fat(m, 0, 0x0FFFFFF8);
    set_fat(m, 1, eoc(m));
}

static void mk_exfat(mk_t *m, unsigned bps_sh, unsigned spc_sh, uint32_t ncl, uint32_t part_lba)
{
    uint32_t bps = 1u << bps_sh, spc = 1u << spc_sh, fat_off = 24;
    uint32_t fat_len = ((ncl + 2) * 4 + bps - 1) / bps;
    uint32_t heap = (fat_off + fat_len + spc - 1) / spc * spc;
    uint64_t total = heap + (uint64_t)ncl * spc;

    memset(m, 0, sizeof *m);
    m->vol = (uint64_t)part_lba * 512;
    m->size = m->vol + total * bps;
    m->img = calloc(1, (size_t)m->size);
    if (part_lba)
        mbr_entry(m->img, 0, 0x07, part_lba, (uint32_t)(total * bps / 512));
    uint8_t *b = m->img + m->vol;
    b[0] = 0xEB; b[1] = 0x76; b[2] = 0x90;
    memcpy(b + 3, "EXFAT   ", 8);
    put64(b + 0x40, part_lba);
    put64(b + 0x48, total);
    put32(b + 0x50, fat_off);
    put32(b + 0x54, fat_len);
    put32(b + 0x58, heap);
    put32(b + 0x5C, ncl);
    put32(b + 0x60, 4);
    put16(b + 0x68, 0x0100);
    b[0x6C] = (uint8_t)bps_sh;
    b[0x6D] = (uint8_t)spc_sh;
    b[0x6E] = 1;
    b[0x6F] = 0x80;
    b[510] = 0x55; b[511] = 0xAA;

    m->type = EXF;
    m->bps = bps;
    m->cb = bps << spc_sh;
    m->ncl = ncl;
    m->fat[0] = m->vol + (uint64_t)fat_off * bps;
    m->nfat_write = 1;
    m->heap = m->vol + (uint64_t)heap * bps;
    set_fat(m, 0, 0xFFFFFFF8);
    set_fat(m, 1, 0xFFFFFFFF);
}

/* directory writer: n == 0 means the FAT12/16 fixed root */
typedef struct {
    mk_t *m;
    uint32_t cl[8];
    size_t n;
    uint64_t pos;
} md_t;

static void md_init(md_t *d, mk_t *m, const uint32_t *cl, size_t n, int link)
{
    d->m = m;
    d->n = n;
    d->pos = 0;
    if (n)
        memcpy(d->cl, cl, n * sizeof *cl);
    if (n && link)
        chain(m, cl, n);
}

static uint8_t *dent(md_t *d)
{
    uint64_t off;
    if (!d->n) {
        off = d->m->root + d->pos;
    } else {
        size_t i = (size_t)(d->pos / d->m->cb);
        if (i >= d->n) {
            printf("test bug: directory full\n");
            exit(2);
        }
        off = coff(d->m, d->cl[i]) + d->pos % d->m->cb;
    }
    d->pos += 32;
    return d->m->img + off;
}

static uint8_t sfn_sum(const char *s)
{
    uint8_t x = 0;
    for (int i = 0; i < 11; i++)
        x = (uint8_t)(((x & 1) << 7) + (x >> 1) + (uint8_t)s[i]);
    return x;
}

static void fat_add(md_t *d, const uint16_t *ln, size_t lnn, const char *sfn, uint8_t attr, uint32_t first,
                    uint32_t size, int deleted, int bad_sum)
{
    static const uint8_t pos[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    uint8_t cs = (uint8_t)(sfn_sum(sfn) ^ (bad_sum ? 0x5A : 0));
    if (ln) {
        unsigned ne = (unsigned)((lnn + 12) / 13);
        for (unsigned s = ne; s >= 1; s--) {
            uint8_t *e = dent(d);
            e[0] = (uint8_t)(s | (s == ne ? 0x40 : 0));
            e[11] = 0x0F;
            e[13] = cs;
            for (unsigned k = 0; k < 13; k++) {
                size_t i = (s - 1) * 13 + k;
                put16(e + pos[k], i < lnn ? ln[i] : i == lnn ? 0 : 0xFFFF);
            }
            if (deleted)
                e[0] = 0xE5;
        }
    }
    uint8_t *e = dent(d);
    memcpy(e, sfn, 11);
    e[11] = attr;
    put16(e + 20, first >> 16);
    put16(e + 26, first & 0xFFFF);
    put32(e + 28, size);
    if (deleted)
        e[0] = 0xE5;
}

static void fat_add_a(md_t *d, const char *ln, const char *sfn, uint8_t attr, uint32_t first, uint32_t size)
{
    uint16_t u[260];
    size_t n = ln ? u16s(ln, u) : 0;
    fat_add(d, ln ? u : NULL, n, sfn, attr, first, size, 0, 0);
}

static void ex_add(md_t *d, const uint16_t *nm, size_t nn, uint16_t attr, uint32_t first, uint64_t size,
                   uint64_t vdl, int nofat, int deleted, int bad_sum)
{
    uint8_t set[19 * 32];
    unsigned ns = (unsigned)((nn + 14) / 15), sc = 1 + ns;
    memset(set, 0, sizeof set);
    set[0] = 0x85;
    set[1] = (uint8_t)sc;
    put16(set + 4, attr);
    uint8_t *s = set + 32;
    s[0] = 0xC0;
    s[1] = (uint8_t)((first ? 1 : 0) | (nofat ? 2 : 0));
    s[3] = (uint8_t)nn;
    put64(s + 8, vdl);
    put32(s + 20, first);
    put64(s + 24, size);
    for (unsigned i = 0; i < ns; i++) {
        uint8_t *e = set + 64 + 32 * i;
        e[0] = 0xC1;
        for (unsigned k = 0; k < 15; k++) {
            size_t idx = 15 * i + k;
            put16(e + 2 + 2 * k, idx < nn ? nm[idx] : 0);
        }
    }
    uint16_t cs = 0;
    for (unsigned i = 0; i < (sc + 1) * 32; i++) {
        if (i == 2 || i == 3)
            continue;
        cs = (uint16_t)(((cs & 1) ? 0x8000 : 0) + (cs >> 1) + set[i]);
    }
    put16(set + 2, (uint16_t)(cs ^ (bad_sum ? 1 : 0)));
    for (unsigned i = 0; i <= sc; i++) {
        if (deleted)
            set[32 * i] &= 0x7F;
        memcpy(dent(d), set + 32 * i, 32);
    }
}

static void ex_add_a(md_t *d, const char *nm, uint16_t attr, uint32_t first, uint64_t size, int nofat)
{
    uint16_t u[260];
    size_t n = u16s(nm, u);
    ex_add(d, u, n, attr, first, size, size, nofat, 0, 0);
}

static int mount_mem(gc_fat_t *fs, memdev_t *md, const uint8_t *img, uint64_t size)
{
    md->p = img;
    md->size = size;
    md->fail = 0;
    gc_bdev_t dev = {mem_read, md};
    return gc_fat_mount(fs, &dev);
}

static void check_file(gc_fat_t *fs, const memdev_t *md, const char *tag, const char *path,
                       const uint8_t *want, uint64_t size, long want_runs)
{
    uint64_t got_size = ~0ull;
    int rc = gc_fat_stat(fs, path, &got_size);
    ck(rc == 0 && got_size == size, "%s stat '%s' rc=%d size=%llu want %llu", tag, path, rc,
       (unsigned long long)got_size, (unsigned long long)size);
    if (rc)
        return;

    uint8_t *buf = malloc((size_t)size + 1);
    rc = gc_fat_read(fs, path, 0, buf, (size_t)size);
    ck(rc == 0 && !memcmp(buf, want, (size_t)size), "%s read whole (%llu bytes) rc=%d", tag,
       (unsigned long long)size, rc);

    /* assorted offsets: cluster and sector edges plus pseudo-random spans */
    const uint64_t cb = fs->cluster_bytes;
    uint64_t offs[64][2];
    size_t no = 0;
    uint64_t fixed[][2] = {{0, 1}, {1, 511}, {511, 2}, {511, 513}, {cb - 1, 2}, {cb - 3, cb + 7},
                           {cb, cb}, {2 * cb - 1, 3 * cb + 1}, {size - 1, 1}, {size / 2, size - size / 2},
                           {size - 1000, 1000}};
    for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
        if (size && fixed[i][0] < size && fixed[i][1] <= size - fixed[i][0])
            { offs[no][0] = fixed[i][0]; offs[no][1] = fixed[i][1]; no++; }
    uint32_t x = 12345;
    while (size && no < 64) {
        x = x * 1103515245u + 12345u;
        uint64_t o = ((uint64_t)x << 16 ^ (x >> 7)) % size;
        x = x * 1103515245u + 12345u;
        uint64_t l = (x >> 8) % (4 * cb + 1000);
        if (l > size - o)
            l = size - o;
        offs[no][0] = o; offs[no][1] = l; no++;
    }
    int bad = 0;
    for (size_t i = 0; i < no; i++) {
        memset(buf, 0xCC, (size_t)offs[i][1]);
        rc = gc_fat_read(fs, path, offs[i][0], buf, (size_t)offs[i][1]);
        if (rc || memcmp(buf, want + offs[i][0], (size_t)offs[i][1])) {
            if (!bad)
                printf("     first mismatch off=%llu len=%llu rc=%d\n", (unsigned long long)offs[i][0],
                       (unsigned long long)offs[i][1], rc);
            bad++;
        }
    }
    ck(!bad, "%s %zu partial reads", tag, no);

    ck(gc_fat_read(fs, path, size, buf, 1) < 0 && (size == 0 || gc_fat_read(fs, path, size - 1, buf, 2) < 0) &&
       gc_fat_read(fs, path, 0, buf, (size_t)size + 1) < 0 && gc_fat_read(fs, path, size, buf, 0) == 0,
       "%s reads past EOF rejected, zero-length read ok", tag);

    static gc_run_t runs[4096];
    size_t n = 99;
    rc = gc_fat_runs(fs, path, runs, 4096, &n);
    uint64_t total = 0;
    int content_ok = rc == 0;
    uint64_t pos = 0;
    for (size_t i = 0; rc == 0 && i < n; i++) {
        total += runs[i].count;
        for (uint64_t s = 0; s < runs[i].count && pos < size; s++, pos += 512) {
            uint64_t o = (runs[i].sd_sector + s) * 512;
            uint64_t take = size - pos < 512 ? size - pos : 512;
            if (o + 512 > md->size || memcmp(md->p + o, want + pos, (size_t)take))
                content_ok = 0;
        }
        if (i && runs[i - 1].sd_sector + runs[i - 1].count == runs[i].sd_sector)
            content_ok = 0; /* unmerged neighbours */
    }
    ck(rc == 0 && content_ok && total == (size + 511) / 512 && (want_runs < 0 || (long)n == want_runs),
       "%s runs: rc=%d n=%zu (want %ld) sectors=%llu content=%s", tag, rc, n, want_runs,
       (unsigned long long)total, content_ok ? "match" : "MISMATCH");
    if (rc == 0 && n > 0) {
        size_t n2 = 77;
        rc = gc_fat_runs(fs, path, runs, n - 1, &n2);
        ck(rc == -1 && n2 == 0, "%s runs overflow at max_runs=%zu -> rc=%d", tag, n - 1, rc);
    }
    free(buf);
}

static void check_err(gc_fat_t *fs, const char *tag, const char *path, int want_rc)
{
    uint64_t sz;
    uint8_t b[16];
    gc_run_t r[GC_MAX_RUNS];
    size_t n;
    int a = gc_fat_stat(fs, path, &sz), bb = gc_fat_read(fs, path, 0, b, 1),
        c = gc_fat_runs(fs, path, r, GC_MAX_RUNS, &n);
    ck(a == want_rc && bb == want_rc && c == want_rc, "%s '%s' -> stat %d read %d runs %d (want %d)", tag, path, a,
       bb, c, want_rc);
}

static void test_fat12(void)
{
    mk_t m;
    md_t root, games;
    gc_fat_t fs;
    memdev_t md;
    mk_fat(&m, 12, 1024, 2, 2048, 64, 0, 0); /* bare, 1 KiB sectors, 2 KiB clusters */

    md_init(&root, &m, NULL, 0, 0);
    uint8_t *e = dent(&root);
    memcpy(e, "GCVOLUME   ", 11);
    e[11] = 0x08;
    uint8_t *readme = pattern(100, 1);
    uint32_t c3 = 3;
    chain(&m, &c3, 1);
    write_data(&m, &c3, 1, readme, 100);
    fat_add_a(&root, NULL, "README  TXT", 0x20, 3, 100);
    uint32_t gcl[2] = {5, 900};
    fat_add_a(&root, "Games", "GAMES      ", 0x10, 5, 0);

    md_init(&games, &m, gcl, 2, 1);
    fat_add_a(&games, NULL, ".          ", 0x10, 5, 0);
    fat_add_a(&games, NULL, "..         ", 0x10, 0, 0);
    char sfn[12];
    for (int i = 0; i < 70; i++) { /* push the target into the second dir cluster */
        snprintf(sfn, sizeof sfn, "FILL%04dBIN", i);
        fat_add_a(&games, NULL, sfn, 0x20, 0, 0);
    }
    /* chain crosses the FAT12 entry that straddles FAT sectors (cluster 682) */
    static const uint32_t ext[] = {680, 5, 10, 3, 700, 1};
    uint32_t cl[16];
    size_t ncl = ext_list(cl, ext, 3);
    uint64_t size = (uint64_t)ncl * m.cb - 777;
    uint8_t *data = pattern(size, 2);
    chain(&m, cl, ncl);
    write_data(&m, cl, ncl, data, size);
    fat_add_a(&games, "My Long Mixed-Case Name.xci", "MYLONG~1XCI", 0x20, cl[0], (uint32_t)size);
    fat_add_a(&games, "Empty File.bin", "EMPTYF~1BIN", 0x20, 0, 0);

    int rc = mount_mem(&fs, &md, m.img, m.size);
    ck(rc == 0 && fs.type == GC_FAT_12 && fs.part_lba == 0 && fs.cluster_bytes == 2048,
       "fat12 mount bare 1K-sector rc=%d type=%d", rc, fs.type);
    check_file(&fs, &md, "fat12", "README.TXT", readme, 100, 1);
    check_file(&fs, &md, "fat12", "games/my long mixed-case name.XCI", data, size, (long)count_runs(cl, ncl));
    check_file(&fs, &md, "fat12", "GAMES/MYLONG~1.XCI", data, size, -1);
    check_file(&fs, &md, "fat12", "Games/../Games/./My Long Mixed-Case Name.xci", data, size, -1);
    check_file(&fs, &md, "fat12", "Games/Empty File.bin", data, 0, 0);
    check_err(&fs, "fat12", "Games/nothere.bin", GC_FAT_ENOENT);
    check_err(&fs, "fat12", "Games", GC_FAT_ENOTFILE);
    check_err(&fs, "fat12", "README.TXT/x", GC_FAT_ENOTFILE);
    check_err(&fs, "fat12", "GCVOLUME", GC_FAT_ENOENT);
    free(readme);
    free(data);
    free(m.img);
}

static void test_fat16(void)
{
    mk_t m;
    md_t root, adir, sub;
    gc_fat_t fs;
    memdev_t md;
    mk_fat(&m, 16, 512, 4, 20000, 512, 63, 0); /* MBR at LBA 63 behind a decoy entry */

    md_init(&root, &m, NULL, 0, 0);
    uint32_t a = 20, s2[2] = {30, 31};
    fat_add_a(&root, "A Dir", "ADIR~1     ", 0x10, a, 0);
    md_init(&adir, &m, &a, 1, 1);
    fat_add_a(&adir, NULL, ".          ", 0x10, a, 0);
    fat_add_a(&adir, NULL, "..         ", 0x10, 0, 0);
    fat_add_a(&adir, "Sub Directory Two", "SUBDIR~1   ", 0x10, s2[0], 0);
    md_init(&sub, &m, s2, 2, 1);
    fat_add_a(&sub, NULL, ".          ", 0x10, s2[0], 0);
    fat_add_a(&sub, NULL, "..         ", 0x10, a, 0);

    uint16_t cafe[32];
    size_t cn = u16s("Caf? Long.bin", cafe);
    cafe[3] = 0x00E9; /* e-acute */
    /* deleted entry with the same name pointing at decoy data */
    uint32_t dc = 200;
    uint8_t *decoy = pattern(2048, 99);
    chain(&m, &dc, 1);
    write_data(&m, &dc, 1, decoy, 2048);
    fat_add(&sub, cafe, cn, "CAFLON~1BIN", 0x20, dc, 2048, 1, 0);

    static const uint32_t ext[] = {100, 10, 50, 3, 4000, 6};
    uint32_t cl[32];
    size_t ncl = ext_list(cl, ext, 3);
    uint64_t size = (uint64_t)ncl * m.cb - 100;
    uint8_t *data = pattern(size, 3);
    chain(&m, cl, ncl);
    write_data(&m, cl, ncl, data, size);
    fat_add(&sub, cafe, cn, "CAFLON~1BIN", 0x20, cl[0], (uint32_t)size, 0, 0);

    /* LFN with a wrong checksum must not attach to the short entry */
    uint16_t on[32];
    size_t onn = u16s("Orphan Name.bin", on);
    uint32_t oc = 300;
    uint8_t *odata = pattern(10, 4);
    chain(&m, &oc, 1);
    write_data(&m, &oc, 1, odata, 10);
    fat_add(&root, on, onn, "ORPHAN  BIN", 0x20, oc, 10, 0, 1);

    /* 13 chars: LFN entry without a NUL terminator */
    uint8_t *t13 = pattern(1500, 6);
    uint32_t tcl = 302;
    chain(&m, &tcl, 1);
    write_data(&m, &tcl, 1, t13, 1500);
    fat_add_a(&root, "ExactlyThirt3", "EXACTL~1   ", 0x20, tcl, 1500);

    int rc = mount_mem(&fs, &md, m.img, m.size);
    ck(rc == 0 && fs.type == GC_FAT_16 && fs.part_lba == 63, "fat16 mount via MBR (LBA 63, decoy skipped) rc=%d",
       rc);
    check_file(&fs, &md, "fat16", "a dir/SUB DIRECTORY TWO/Caf\xc3\xa9 long.BIN", data, size,
               (long)count_runs(cl, ncl));
    check_file(&fs, &md, "fat16", "ADIR~1/SUBDIR~1/CAFLON~1.BIN", data, size, -1);
    check_file(&fs, &md, "fat16", "ORPHAN.BIN", odata, 10, 1);
    check_err(&fs, "fat16", "Orphan Name.bin", GC_FAT_ENOENT);
    check_file(&fs, &md, "fat16", "exactlythirt3", t13, 1500, 1);
    check_err(&fs, "fat16", "A Dir/Sub Directory Two/Cafe Long.bin", GC_FAT_ENOENT);
    free(decoy);
    free(data);
    free(odata);
    free(t13);
    free(m.img);
}

static void test_fat32(void)
{
    mk_t m;
    md_t root, l1, l2, l3, loopd;
    gc_fat_t fs;
    memdev_t md;
    mk_fat(&m, 32, 512, 1, 68000, 0, 0, 1); /* bare, 512 B clusters, FAT mirroring off (FAT #1 live) */

    uint32_t rcl[3] = {2, 3, 50000};
    md_init(&root, &m, rcl, 3, 1);
    char sfn[12];
    for (int i = 0; i < 20; i++) {
        snprintf(sfn, sizeof sfn, "PAD%05d   ", i);
        fat_add_a(&root, NULL, sfn, 0x20, 0, 0);
    }

    /* 600 one-cluster extents -> 600 runs (> GC_MAX_RUNS) */
    static uint32_t many[600];
    for (int i = 0; i < 600; i++)
        many[i] = 1000 + 2 * (uint32_t)i;
    uint64_t msize = 600ull * 512 - 13;
    uint8_t *mdata = pattern(msize, 7);
    chain(&m, many, 600);
    write_data(&m, many, 600, mdata, msize);
    fat_add_a(&root, "Frag Many Runs.bin", "FRAGMA~1BIN", 0x20, many[0], (uint32_t)msize);

    uint8_t *d26 = pattern(700, 8);
    uint32_t c26[2] = {2500, 2501};
    chain(&m, c26, 2);
    write_data(&m, c26, 2, d26, 700);
    fat_add_a(&root, "ExactlyTwentySixCharacters", "EXACTL~1   ", 0x20, c26[0], 700);

    /* clusters above 65535 exercise the high word in the dir entry */
    static const uint32_t hiext[] = {66000, 4, 7, 1};
    uint32_t hcl[8];
    size_t hn = ext_list(hcl, hiext, 2);
    uint64_t hsize = hn * 512ull - 1;
    uint8_t *hdata = pattern(hsize, 9);
    chain(&m, hcl, hn);
    write_data(&m, hcl, hn, hdata, hsize);
    fat_add_a(&root, "High Cluster.bin", "HIGHCL~1BIN", 0x20, hcl[0], (uint32_t)hsize);

    /* corrupt chains */
    set_fat(&m, 5000, 5001);
    set_fat(&m, 5001, 5000);
    fat_add_a(&root, "loop.bin", "LOOP    BIN", 0x20, 5000, 10 * 512);
    uint32_t sc[2] = {5100, 5101};
    chain(&m, sc, 2);
    fat_add_a(&root, "short.bin", "SHORT   BIN", 0x20, 5100, 5 * 512);
    set_fat(&m, 5200, 5201); /* 5201 stays free */
    fat_add_a(&root, "free.bin", "FREE    BIN", 0x20, 5200, 3 * 512);
    set_fat(&m, 5250, 0x0FFFFFF7); /* bad cluster marker */
    fat_add_a(&root, "bad.bin", "BAD     BIN", 0x20, 5250, 2 * 512);

    /* directory whose chain loops onto itself, no end marker entry */
    uint32_t lc = 5300;
    md_init(&loopd, &m, &lc, 1, 0);
    set_fat(&m, 5300, 5300);
    for (int i = 0; i < 16; i++) {
        snprintf(sfn, sizeof sfn, "JUNK%04dBIN", i);
        fat_add_a(&loopd, NULL, sfn, 0x20, 0, 0);
    }
    fat_add_a(&root, "LoopDir", "LOOPDIR    ", 0x10, lc, 0);

    /* chain longer than the size: only the needed clusters are mapped */
    uint32_t tl[3] = {6000, 6001, 6002};
    chain(&m, tl, 3);
    uint8_t one = 0x5C;
    m.img[coff(&m, 6000)] = one;
    fat_add_a(&root, "Tail.bin", "TAIL    BIN", 0x20, 6000, 1);
    fat_add_a(&root, "zero.bin", "ZERO    BIN", 0x20, 0, 0);

    /* nested L1/L2/L3 */
    uint32_t c1 = 7000, c2 = 7001, c3 = 7002;
    fat_add_a(&root, "L1", "L1         ", 0x10, c1, 0);
    md_init(&l1, &m, &c1, 1, 1);
    fat_add_a(&l1, "L2", "L2         ", 0x10, c2, 0);
    md_init(&l2, &m, &c2, 1, 1);
    fat_add_a(&l2, "L3", "L3         ", 0x10, c3, 0);
    md_init(&l3, &m, &c3, 1, 1);
    static const uint32_t dext[] = {8000, 3, 7500, 2, 8003, 4};
    uint32_t dcl[16];
    size_t dn = ext_list(dcl, dext, 3);
    uint64_t dsize = dn * 512ull - 200;
    uint8_t *ddata = pattern(dsize, 10);
    chain(&m, dcl, dn);
    write_data(&m, dcl, dn, ddata, dsize);
    fat_add_a(&l3, "Deep File.dat", "DEEPFI~1DAT", 0x20, dcl[0], (uint32_t)dsize);

    int rc = mount_mem(&fs, &md, m.img, m.size);
    ck(rc == 0 && fs.type == GC_FAT_32 && fs.cluster_count == m.ncl, "fat32 mount bare, active FAT #1 rc=%d", rc);
    check_file(&fs, &md, "fat32", "frag many runs.bin", mdata, msize, 600);
    {
        gc_run_t r[GC_MAX_RUNS];
        size_t n = 5;
        rc = gc_fat_runs(&fs, "Frag Many Runs.bin", r, GC_MAX_RUNS, &n);
        ck(rc == -1 && n == 0, "fat32 600 runs vs GC_MAX_RUNS -> rc=%d", rc);
    }
    check_file(&fs, &md, "fat32", "EXACTLYTWENTYSIXCHARACTERS", d26, 700, 1);
    check_file(&fs, &md, "fat32", "High Cluster.bin", hdata, hsize, 2);
    check_file(&fs, &md, "fat32", "L1/L2/L3/Deep File.dat", ddata, dsize, (long)count_runs(dcl, dn));
    check_file(&fs, &md, "fat32", "/L1//l2/L3/deep file.DAT", ddata, dsize, -1);
    check_file(&fs, &md, "fat32", "Tail.bin", &one, 1, 1);
    check_file(&fs, &md, "fat32", "zero.bin", &one, 0, 0);

    uint8_t buf[10 * 512];
    gc_run_t r[GC_MAX_RUNS];
    size_t n;
    uint64_t sz;
    const char *bad[] = {"loop.bin", "short.bin", "free.bin", "bad.bin"};
    for (int i = 0; i < 4; i++) {
        int s = gc_fat_stat(&fs, bad[i], &sz);
        int rd = gc_fat_read(&fs, bad[i], 0, buf, (size_t)sz);
        int rr = gc_fat_runs(&fs, bad[i], r, GC_MAX_RUNS, &n);
        ck(s == 0 && rd == GC_FAT_ECORRUPT && rr == GC_FAT_ECORRUPT, "fat32 corrupt chain %s: read %d runs %d",
           bad[i], rd, rr);
    }
    rc = gc_fat_stat(&fs, "LoopDir/missing.bin", &sz);
    ck(rc == GC_FAT_ECORRUPT, "fat32 looping directory chain terminates rc=%d", rc);
    free(mdata);
    free(d26);
    free(hdata);
    free(ddata);
    free(m.img);
}

static void test_fat32_4k(void)
{
    mk_t m;
    md_t root, dir;
    gc_fat_t fs;
    memdev_t md;
    mk_fat(&m, 32, 4096, 1, 66300, 0, 2048, 0); /* 4 KiB sectors, MBR at 1 MiB */
    uint32_t rc2 = 2, dc = 10;
    md_init(&root, &m, &rc2, 1, 1);
    fat_add_a(&root, "dir", "DIR        ", 0x10, dc, 0);
    md_init(&dir, &m, &dc, 1, 1);
    static const uint32_t ext[] = {70, 5, 65000, 4};
    uint32_t cl[16];
    size_t n = ext_list(cl, ext, 2);
    uint64_t size = n * 4096ull - 4000;
    uint8_t *data = pattern(size, 11);
    chain(&m, cl, n);
    write_data(&m, cl, n, data, size);
    fat_add_a(&dir, "Big Sector File.bin", "BIGSEC~1BIN", 0x20, cl[0], (uint32_t)size);

    int rc = mount_mem(&fs, &md, m.img, m.size);
    ck(rc == 0 && fs.type == GC_FAT_32 && fs.part_lba == 2048 && fs.cluster_bytes == 4096,
       "fat32 4K-sector mount via MBR rc=%d", rc);
    check_file(&fs, &md, "fat32-4k", "dir/big sector file.bin", data, size, 2);
    free(data);
    free(m.img);
}

static void test_exfat(void)
{
    mk_t m;
    md_t root, games;
    gc_fat_t fs;
    memdev_t md;
    mk_exfat(&m, 9, 3, 3000, 2048); /* 4 KiB clusters, MBR type 0x07 */

    uint32_t rcl[2] = {4, 9};
    md_init(&root, &m, rcl, 2, 1);
    uint8_t *e = dent(&root);
    e[0] = 0x83; /* volume label */
    e = dent(&root);
    e[0] = 0x81; /* allocation bitmap */
    put32(e + 20, 2);
    e = dent(&root);
    e[0] = 0x82; /* up-case table */
    put32(e + 20, 3);
    char nm[32];
    for (int i = 0; i < 50; i++) { /* 150 entries: spills into the 2nd root cluster */
        snprintf(nm, sizeof nm, "filler%02d", i);
        ex_add_a(&root, nm, 0x20, 0, 0, 0);
    }
    uint32_t gcl[2] = {20, 25};
    ex_add_a(&root, "Games Folder", 0x10, gcl[0], 2ull * m.cb, 0);
    md_init(&games, &m, gcl, 2, 1);

    uint16_t u[64];
    size_t un = u16s("My Long Mixed-Case Name.xci", u);
    uint32_t dc = 400;
    uint8_t *decoy = pattern(4096, 98);
    chain(&m, &dc, 1);
    write_data(&m, &dc, 1, decoy, 4096);
    ex_add(&games, u, un, 0x20, dc, 4096, 4096, 0, 1, 0); /* deleted set */

    static const uint32_t ext[] = {100, 5, 30, 2, 2000, 3};
    uint32_t cl[16];
    size_t n = ext_list(cl, ext, 3);
    uint64_t size = n * 4096ull - 1000;
    uint8_t *data = pattern(size, 12);
    chain(&m, cl, n);
    write_data(&m, cl, n, data, size);
    ex_add(&games, u, un, 0x20, cl[0], size, size, 0, 0, 0);

    /* NoFatChain: contiguous, FAT entries left free */
    uint32_t ccl[7];
    for (int i = 0; i < 7; i++)
        ccl[i] = 500 + (uint32_t)i;
    uint64_t csize = 7 * 4096ull - 5;
    uint8_t *cdata = pattern(csize, 13);
    write_data(&m, ccl, 7, cdata, csize);
    ex_add_a(&games, "Contiguous Game Image With A Very Long Name.xci", 0x20, 500, csize, 1);

    /* ValidDataLength < DataLength: tail reads as zero, runs refused */
    uint32_t vcl[3] = {600, 601, 602};
    uint8_t *vdisk = pattern(3 * 4096, 14), *vwant = malloc(3 * 4096);
    memcpy(vwant, vdisk, 5000);
    memset(vwant + 5000, 0, 3 * 4096 - 5000);
    chain(&m, vcl, 3);
    write_data(&m, vcl, 3, vdisk, 3 * 4096);
    {
        size_t sn = u16s("Sparse.bin", u);
        ex_add(&games, u, sn, 0x20, 600, 3 * 4096, 5000, 0, 0, 0);
        sn = u16s("BadSum.bin", u);
        ex_add(&games, u, sn, 0x20, 600, 4096, 4096, 0, 0, 1);
        sn = u16s("Caf? Ex.bin", u);
        u[3] = 0x00E9;
        ex_add(&games, u, sn, 0x20, 600, 5000, 5000, 0, 0, 0);
    }
    ex_add_a(&games, "Empty.bin", 0x20, 0, 0, 0);

    int rc = mount_mem(&fs, &md, m.img, m.size);
    ck(rc == 0 && fs.type == GC_FAT_EX && fs.part_lba == 2048 && fs.cluster_bytes == 4096,
       "exfat mount via MBR rc=%d type=%d", rc, fs.type);
    check_file(&fs, &md, "exfat", "games folder/MY LONG MIXED-CASE NAME.xci", data, size, (long)count_runs(cl, n));
    check_file(&fs, &md, "exfat", "Games Folder/contiguous game image with a very long name.XCI", cdata, csize, 1);
    check_file(&fs, &md, "exfat", "Games Folder/Caf\xc3\xa9 Ex.bin", vdisk, 5000, 1);
    check_file(&fs, &md, "exfat", "Games Folder/Empty.bin", data, 0, 0);
    check_err(&fs, "exfat", "Games Folder/BadSum.bin", GC_FAT_ENOENT);
    check_err(&fs, "exfat", "filler07/x", GC_FAT_ENOTFILE);
    {
        uint8_t b[3 * 4096];
        memset(b, 0xEE, sizeof b);
        rc = gc_fat_read(&fs, "Games Folder/Sparse.bin", 0, b, sizeof b);
        ck(rc == 0 && !memcmp(b, vwant, sizeof b), "exfat VDL tail reads as zero rc=%d", rc);
        rc = gc_fat_read(&fs, "Games Folder/Sparse.bin", 4999, b, 2);
        ck(rc == 0 && b[0] == vwant[4999] && b[1] == 0, "exfat VDL boundary read rc=%d", rc);
        gc_run_t r[4];
        size_t rn;
        rc = gc_fat_runs(&fs, "Games Folder/Sparse.bin", r, 4, &rn);
        ck(rc == GC_FAT_EUNSUP, "exfat runs refuse VDL<size rc=%d", rc);
    }
    free(decoy);
    free(data);
    free(cdata);
    free(vdisk);
    free(vwant);
    free(m.img);
}

static void test_exfat_big_cluster(void)
{
    mk_t m;
    md_t root, cdir;
    gc_fat_t fs;
    memdev_t md;
    mk_exfat(&m, 12, 5, 64, 0); /* 4 KiB sectors, 128 KiB clusters, bare */
    uint32_t r4 = 4;
    md_init(&root, &m, &r4, 1, 1);
    /* contiguous (NoFatChain) directory spanning two clusters */
    ex_add_a(&root, "Contig Dir", 0x10, 10, 2ull * m.cb, 1);
    uint32_t dcl[2] = {10, 11};
    md_init(&cdir, &m, dcl, 2, 0);
    char nm[16];
    for (int i = 0; i < 1400; i++) { /* 4200 entries > 4096 per cluster */
        snprintf(nm, sizeof nm, "f%04d", i);
        ex_add_a(&cdir, nm, 0x20, 0, 0, 0);
    }
    static const uint32_t ext[] = {40, 2, 20, 3};
    uint32_t cl[8];
    size_t n = ext_list(cl, ext, 2);
    uint64_t size = n * (uint64_t)m.cb - 70000;
    uint8_t *data = pattern(size, 15);
    chain(&m, cl, n);
    write_data(&m, cl, n, data, size);
    ex_add_a(&cdir, "Payload In Second Cluster.bin", 0x20, cl[0], size, 0);

    int rc = mount_mem(&fs, &md, m.img, m.size);
    ck(rc == 0 && fs.type == GC_FAT_EX && fs.cluster_bytes == 128 * 1024, "exfat 128K-cluster bare mount rc=%d",
       rc);
    check_file(&fs, &md, "exfat-128k", "contig dir/payload in second cluster.bin", data, size, 2);
    free(data);
    free(m.img);
}

static void test_mount_errors(void)
{
    gc_fat_t fs;
    memdev_t md;
    uint8_t *z = calloc(1, 1 << 20);
    int rc = mount_mem(&fs, &md, z, 1 << 20);
    ck(rc == GC_FAT_EUNSUP, "mount zeroed device -> rc=%d", rc);
    mbr_entry(z, 0, 0x0C, 4096, 100); /* partition beyond the device */
    rc = mount_mem(&fs, &md, z, 1 << 20);
    ck(rc < 0, "mount MBR pointing past device -> rc=%d", rc);
    md.fail = 1;
    gc_bdev_t dev = {mem_read, &md};
    rc = gc_fat_mount(&fs, &dev);
    ck(rc == GC_FAT_EIO, "mount with failing device -> rc=%d", rc);
    uint64_t sz;
    ck(gc_fat_stat(&fs, "x", &sz) == GC_FAT_EINVAL, "stat on unmounted fs rejected");
    free(z);
}

static uint8_t *slurp(const char *path, uint64_t *size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    size_t cap = 1 << 20, n = 0, r;
    uint8_t *p = malloc(cap);
    while ((r = fread(p + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap)
            p = realloc(p, cap *= 2);
    }
    fclose(f);
    *size = n;
    return p;
}

static void test_real(const char *img_path, const char *inner, const char *host)
{
    uint64_t isz, hsz;
    uint8_t *img = slurp(img_path, &isz), *want = slurp(host, &hsz);
    if (!img || !want) {
        ck(0, "real: cannot read %s or %s", img_path, host);
        free(img);
        free(want);
        return;
    }
    gc_fat_t fs;
    memdev_t md;
    int rc = mount_mem(&fs, &md, img, isz);
    static const char *tn[] = {"none", "FAT12", "FAT16", "FAT32", "exFAT"};
    ck(rc == 0, "real %s: mount rc=%d %s part_lba=%llu cluster=%u clusters=%u", img_path, rc, tn[fs.type],
       (unsigned long long)fs.part_lba, fs.cluster_bytes, fs.cluster_count);
    if (!rc) {
        char tag[512];
        snprintf(tag, sizeof tag, "real %s", img_path);
        check_file(&fs, &md, tag, inner, want, hsz, -1);
        gc_run_t r[GC_MAX_RUNS];
        size_t n = 0;
        if (gc_fat_runs(&fs, inner, r, GC_MAX_RUNS, &n) == 0)
            printf("     %zu run(s); first at sector %llu\n", n, n ? (unsigned long long)r[0].sd_sector : 0ull);
    }
    free(img);
    free(want);
}

int main(int argc, char **argv)
{
    test_fat12();
    test_fat16();
    test_fat32();
    test_fat32_4k();
    test_exfat();
    test_exfat_big_cluster();
    test_mount_errors();
    if ((argc - 1) % 3) {
        printf("usage: %s [IMAGE PATH-IN-VOLUME HOST-FILE]...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i + 2 < argc; i += 3)
        test_real(argv[i], argv[i + 1], argv[i + 2]);
    if (fails) {
        printf("\n%d FAILURE(S)\n", fails);
        return 1;
    }
    printf("\nall fat checks pass\n");
    return 0;
}
