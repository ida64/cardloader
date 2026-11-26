/* fat.c - read-only FAT12/FAT16/FAT32/exFAT reader. See fat.h.
 *
 * No allocation and no stdio: all state is in gc_fat_t, all device access goes
 * through gc_bdev_read() in absolute 512-byte sectors.
 */
#include "fat.h"

#define BULK_MAX_SECTORS 0x10000u /* 32 MiB per device call */

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static int cache_load(gc_fat_t *fs, gc_fat_cache_t *c, uint64_t lba)
{
    if (c->valid && c->lba == lba)
        return 0;
    c->valid = 0;
    if (gc_bdev_read(&fs->dev, c->buf, lba, 1))
        return GC_FAT_EIO;
    c->lba = lba;
    c->valid = 1;
    return 0;
}

/* Read len bytes at byte offset off from the volume start. Unaligned edges go
 * through the given one-sector cache; whole sectors go straight to buf. */
static int vol_read(gc_fat_t *fs, gc_fat_cache_t *c, uint64_t off, void *buf, size_t len)
{
    uint8_t *d = (uint8_t *)buf;
    uint64_t lba = fs->part_lba + (off >> GC_SECTOR_SHIFT);
    size_t in = (size_t)(off & (GC_SECTOR_SIZE - 1));

    while (len) {
        size_t n;
        if (in || len < GC_SECTOR_SIZE) {
            int rc = cache_load(fs, c, lba);
            if (rc)
                return rc;
            n = GC_SECTOR_SIZE - in;
            if (n > len)
                n = len;
            memcpy(d, c->buf + in, n);
            in = 0;
            lba++;
        } else {
            size_t secs = len >> GC_SECTOR_SHIFT;
            if (secs > BULK_MAX_SECTORS)
                secs = BULK_MAX_SECTORS;
            if (gc_bdev_read(&fs->dev, d, lba, (uint32_t)secs))
                return GC_FAT_EIO;
            n = secs << GC_SECTOR_SHIFT;
            lba += secs;
        }
        d += n;
        len -= n;
    }
    return 0;
}

static int cluster_ok(const gc_fat_t *fs, uint32_t c)
{
    return c >= 2 && c <= fs->cluster_count + 1;
}

static uint64_t cluster_off(const gc_fat_t *fs, uint32_t c)
{
    return fs->heap_off + (uint64_t)(c - 2) * fs->cluster_bytes;
}

/* 1: *next is the following cluster; 0: end of chain; <0: corrupt / I/O. */
static int chain_next(gc_fat_t *fs, uint32_t c, uint32_t *next)
{
    uint8_t b[4];
    uint32_t v, eoc;
    int rc;

    switch (fs->type) {
    case GC_FAT_12:
        rc = vol_read(fs, &fs->fat_cache, fs->fat_off + c + (c >> 1), b, 2);
        v = rd16(b);
        v = (c & 1) ? (v >> 4) : (v & 0xFFF);
        eoc = 0xFF8;
        break;
    case GC_FAT_16:
        rc = vol_read(fs, &fs->fat_cache, fs->fat_off + (uint64_t)c * 2, b, 2);
        v = rd16(b);
        eoc = 0xFFF8;
        break;
    case GC_FAT_32:
        rc = vol_read(fs, &fs->fat_cache, fs->fat_off + (uint64_t)c * 4, b, 4);
        v = gc_rd32(b) & 0x0FFFFFFF;
        eoc = 0x0FFFFFF8;
        break;
    default: /* exFAT: full 32-bit entries, 0xFFFFFFFF ends the chain */
        rc = vol_read(fs, &fs->fat_cache, fs->fat_off + (uint64_t)c * 4, b, 4);
        v = gc_rd32(b);
        eoc = 0xFFFFFFFF;
        break;
    }
    if (rc)
        return rc;
    if (v >= eoc)
        return 0;
    if (!cluster_ok(fs, v)) /* free, reserved, bad or out of range */
        return GC_FAT_ECORRUPT;
    *next = v;
    return 1;
}

/* Chain walker. Every walk is bounded by cluster_count and runs Brent's cycle
 * detection (one stored cluster, no extra FAT reads). */
typedef struct {
    uint32_t cur;
    uint32_t idx;      /* index of cur within the chain */
    int contig;        /* exFAT NoFatChain: clusters are first, first+1, ... */
    uint32_t tortoise;
    uint64_t power, lam;
} walk_t;

static void walk_init(walk_t *w, uint32_t first, int contig)
{
    w->cur = first;
    w->idx = 0;
    w->contig = contig;
    w->tortoise = first;
    w->power = 1;
    w->lam = 0;
}

/* 1: advanced; 0: end of chain; <0: corrupt / I/O. */
static int walk_step(gc_fat_t *fs, walk_t *w)
{
    uint32_t n;

    if (w->contig) {
        n = w->cur + 1;
        if (!cluster_ok(fs, n))
            return GC_FAT_ECORRUPT;
    } else {
        int rc = chain_next(fs, w->cur, &n);
        if (rc <= 0)
            return rc;
        if (n == w->tortoise)
            return GC_FAT_ECORRUPT;
        if (++w->lam == w->power) {
            w->tortoise = n;
            w->power <<= 1;
            w->lam = 0;
        }
    }
    if (w->idx + 1 >= fs->cluster_count)
        return GC_FAT_ECORRUPT; /* longer than the volume: must loop */
    w->cur = n;
    w->idx++;
    return 1;
}

typedef struct {
    uint32_t first;
    uint64_t size;  /* file size; directory byte limit (UINT64_MAX = chain) */
    uint64_t vdl;   /* exFAT ValidDataLength; == size on FAT */
    int contig;
    int dir;
    int fixed_root; /* FAT12/16 root directory region */
} node_t;

typedef struct {
    node_t n;
    walk_t w;
    uint64_t pos;
} dir_t;

static void root_node(const gc_fat_t *fs, node_t *n)
{
    memset(n, 0, sizeof *n);
    n->dir = 1;
    n->size = UINT64_MAX;
    if (fs->type == GC_FAT_12 || fs->type == GC_FAT_16) {
        n->fixed_root = 1;
        n->size = fs->root_bytes;
    } else {
        n->first = fs->root_cluster;
    }
    n->vdl = n->size;
}

static int dir_open(const gc_fat_t *fs, const node_t *n, dir_t *d)
{
    d->n = *n;
    d->pos = 0;
    if (!n->fixed_root && n->size) {
        if (!cluster_ok(fs, n->first))
            return GC_FAT_ECORRUPT;
        walk_init(&d->w, n->first, n->contig);
    }
    return 0;
}

/* 1: entry read; 0: end of directory storage; <0: error. */
static int dir_next(gc_fat_t *fs, dir_t *d, uint8_t ent[32])
{
    uint64_t off;
    int rc;

    if (d->pos >= d->n.size)
        return 0;
    if (d->n.fixed_root) {
        off = fs->root_off + d->pos;
    } else {
        uint32_t in = (uint32_t)(d->pos % fs->cluster_bytes);
        if (d->pos && !in) {
            rc = walk_step(fs, &d->w);
            if (rc <= 0)
                return rc;
        }
        off = cluster_off(fs, d->w.cur) + in;
    }
    rc = vol_read(fs, &fs->dir_cache, off, ent, 32);
    if (rc)
        return rc;
    d->pos += 32;
    return 1;
}

static size_t utf16_to_utf8(const uint16_t *s, size_t n, char *o)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00u);
            i++;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        if (c < 0x80) {
            o[k++] = (char)c;
        } else if (c < 0x800) {
            o[k++] = (char)(0xC0 | (c >> 6));
            o[k++] = (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            o[k++] = (char)(0xE0 | (c >> 12));
            o[k++] = (char)(0x80 | ((c >> 6) & 0x3F));
            o[k++] = (char)(0x80 | (c & 0x3F));
        } else {
            o[k++] = (char)(0xF0 | (c >> 18));
            o[k++] = (char)(0x80 | ((c >> 12) & 0x3F));
            o[k++] = (char)(0x80 | ((c >> 6) & 0x3F));
            o[k++] = (char)(0x80 | (c & 0x3F));
        }
    }
    return k;
}

static int name_eq(const char *a, size_t an, const char *b, size_t bn)
{
    if (an != bn)
        return 0;
    for (size_t i = 0; i < an; i++) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'a' && x <= 'z') x = (unsigned char)(x - 32);
        if (y >= 'a' && y <= 'z') y = (unsigned char)(y - 32);
        if (x != y)
            return 0;
    }
    return 1;
}

static int u16_name_eq(gc_fat_t *fs, size_t units, const char *nm, size_t nlen)
{
    size_t k = utf16_to_utf8(fs->name16, units, fs->name8);
    return name_eq(fs->name8, k, nm, nlen);
}

static uint8_t sfn_checksum(const uint8_t *e)
{
    uint8_t s = 0;
    for (int i = 0; i < 11; i++)
        s = (uint8_t)(((s & 1) << 7) + (s >> 1) + e[i]);
    return s;
}

static size_t sfn_string(const uint8_t *e, char *o)
{
    size_t k = 0, b = 8, x = 3;
    while (b && e[b - 1] == ' ')
        b--;
    while (x && e[8 + x - 1] == ' ')
        x--;
    for (size_t i = 0; i < b; i++)
        o[k++] = (char)((i == 0 && e[0] == 0x05) ? 0xE5 : e[i]);
    if (x) {
        o[k++] = '.';
        for (size_t i = 0; i < x; i++)
            o[k++] = (char)e[8 + i];
    }
    return k;
}

static int fat_find(gc_fat_t *fs, const node_t *dn, const char *nm, size_t nlen, node_t *out)
{
    static const uint8_t lfn_pos[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    uint8_t e[32];
    dir_t d;
    unsigned lfn_seq = 0, lfn_n = 0; /* lfn_seq: last sequence seen, 0 = none */
    uint8_t lfn_sum = 0;
    int rc = dir_open(fs, dn, &d);
    if (rc)
        return rc;

    for (;;) {
        rc = dir_next(fs, &d, e);
        if (rc < 0)
            return rc;
        if (rc == 0 || e[0] == 0x00)
            return GC_FAT_ENOENT;
        if (e[0] == 0xE5) {
            lfn_seq = 0;
            continue;
        }
        if ((e[11] & 0x3F) == 0x0F) {
            unsigned s = e[0] & 0x1F;
            if (e[0] & 0x40) {
                if (s == 0 || s > 20) {
                    lfn_seq = 0;
                    continue;
                }
                lfn_n = s;
                lfn_sum = e[13];
            } else if (!lfn_seq || s != lfn_seq - 1 || e[13] != lfn_sum) {
                lfn_seq = 0;
                continue;
            }
            lfn_seq = s;
            for (unsigned i = 0; i < 13; i++)
                fs->name16[(s - 1) * 13 + i] = rd16(e + lfn_pos[i]);
            continue;
        }

        int have_lfn = lfn_seq == 1 && sfn_checksum(e) == lfn_sum;
        lfn_seq = 0;
        if (e[11] & 0x08) /* volume label */
            continue;

        int match = 0;
        if (have_lfn) {
            size_t units = 0, max = (size_t)lfn_n * 13;
            while (units < max && fs->name16[units] != 0x0000)
                units++;
            match = u16_name_eq(fs, units, nm, nlen);
        }
        if (!match) {
            size_t k = sfn_string(e, fs->name8);
            match = name_eq(fs->name8, k, nm, nlen);
        }
        if (!match)
            continue;

        memset(out, 0, sizeof *out);
        out->dir = (e[11] & 0x10) != 0;
        out->first = rd16(e + 26);
        if (fs->type == GC_FAT_32)
            out->first |= (uint32_t)rd16(e + 20) << 16;
        if (out->dir) {
            if (out->first == 0) /* ".." of a first-level subdirectory */
                root_node(fs, out);
            else
                out->size = out->vdl = UINT64_MAX;
        } else {
            out->size = out->vdl = gc_rd32(e + 28);
        }
        return 0;
    }
}

static uint16_t exfat_csum(uint16_t s, const uint8_t *e, int primary)
{
    for (int i = 0; i < 32; i++) {
        if (primary && (i == 2 || i == 3))
            continue;
        s = (uint16_t)(((s & 1) ? 0x8000 : 0) + (s >> 1) + e[i]);
    }
    return s;
}

static int exfat_find(gc_fat_t *fs, const node_t *dn, const char *nm, size_t nlen, node_t *out)
{
    uint8_t e[32];
    dir_t d;
    unsigned remain = 0, idx = 0, name_len = 0, name_pos = 0;
    uint16_t csum = 0, want = 0, attr = 0;
    node_t cand;
    int rc = dir_open(fs, dn, &d);
    if (rc)
        return rc;
    memset(&cand, 0, sizeof cand);

    for (;;) {
        rc = dir_next(fs, &d, e);
        if (rc < 0)
            return rc;
        if (rc == 0 || e[0] == 0x00)
            return GC_FAT_ENOENT;

        if (remain) {
            if ((e[0] & 0xC0) == 0xC0) { /* in-use secondary entry */
                csum = exfat_csum(csum, e, 0);
                if (idx == 0) {
                    if (e[0] != 0xC0) {
                        remain = 0; /* set must start with a stream extension */
                        continue;
                    }
                    cand.contig = (e[1] & 0x02) != 0;
                    name_len = e[3];
                    cand.vdl = gc_rd64(e + 8);
                    cand.first = gc_rd32(e + 20);
                    cand.size = gc_rd64(e + 24);
                } else if (e[0] == 0xC1) {
                    for (unsigned i = 0; i < 15 && name_pos < name_len; i++)
                        fs->name16[name_pos++] = rd16(e + 2 + 2 * i);
                }
                idx++;
                if (--remain)
                    continue;
                if (csum != want || !name_len || name_pos != name_len)
                    continue;
                if (!u16_name_eq(fs, name_len, nm, nlen))
                    continue;
                cand.dir = (attr & 0x10) != 0;
                if (cand.vdl > cand.size)
                    return GC_FAT_ECORRUPT;
                *out = cand;
                return 0;
            }
            remain = 0; /* broken set: reconsider this entry as a primary */
        }
        if (e[0] == 0x85 && e[1] >= 2 && e[1] <= 18) {
            remain = e[1];
            idx = 0;
            name_len = name_pos = 0;
            want = rd16(e + 2);
            attr = rd16(e + 4);
            csum = exfat_csum(0, e, 1);
            memset(&cand, 0, sizeof cand);
        }
    }
}

static int lookup(gc_fat_t *fs, const char *path, node_t *out)
{
    node_t cur;
    const char *p = path;

    root_node(fs, &cur);
    for (;;) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *e = p;
        while (*e && *e != '/')
            e++;
        if (!cur.dir)
            return GC_FAT_ENOTFILE;
        node_t next;
        int rc = fs->type == GC_FAT_EX ? exfat_find(fs, &cur, p, (size_t)(e - p), &next)
                                       : fat_find(fs, &cur, p, (size_t)(e - p), &next);
        if (rc)
            return rc;
        cur = next;
        p = e;
    }
    *out = cur;
    return 0;
}

/* Resolve a regular file and sanity-check its allocation against the volume. */
static int open_file(gc_fat_t *fs, const char *path, node_t *n, uint64_t *nclus)
{
    if (!fs || !path || fs->type == GC_FAT_NONE)
        return GC_FAT_EINVAL;
    int rc = lookup(fs, path, n);
    if (rc)
        return rc;
    if (n->dir)
        return GC_FAT_ENOTFILE;
    *nclus = n->size / fs->cluster_bytes + (n->size % fs->cluster_bytes != 0);
    if (!n->size)
        return 0;
    if (*nclus > fs->cluster_count || !cluster_ok(fs, n->first))
        return GC_FAT_ECORRUPT;
    if (n->contig && (uint64_t)n->first - 2 + *nclus > fs->cluster_count)
        return GC_FAT_ECORRUPT;
    return 0;
}

static int parse_exfat(gc_fat_t *fs, const uint8_t *b)
{
    for (int i = 11; i < 64; i++)
        if (b[i])
            return GC_FAT_EUNSUP;
    if (b[510] != 0x55 || b[511] != 0xAA)
        return GC_FAT_EUNSUP;

    unsigned bps_sh = b[0x6C], spc_sh = b[0x6D], nfats = b[0x6E];
    uint32_t fat_offset = gc_rd32(b + 0x50), fat_len = gc_rd32(b + 0x54);
    uint32_t heap = gc_rd32(b + 0x58), count = gc_rd32(b + 0x5C), root = gc_rd32(b + 0x60);

    if (bps_sh < 9 || bps_sh > 12 || spc_sh > 25 - bps_sh || (nfats != 1 && nfats != 2))
        return GC_FAT_ECORRUPT;
    if (!count || count > 0xFFFFFFF5u || fat_offset < 24 || !fat_len)
        return GC_FAT_ECORRUPT;
    if (((uint64_t)count + 2) * 4 > (uint64_t)fat_len << bps_sh)
        return GC_FAT_ECORRUPT;
    if ((uint64_t)heap < (uint64_t)fat_offset + (uint64_t)fat_len * nfats)
        return GC_FAT_ECORRUPT;

    fs->type = GC_FAT_EX;
    fs->cluster_bytes = 1u << (bps_sh + spc_sh);
    fs->cluster_count = count;
    fs->fat_off = ((uint64_t)fat_offset << bps_sh);
    if (nfats == 2 && (rd16(b + 0x6A) & 1)) /* VolumeFlags.ActiveFat */
        fs->fat_off += (uint64_t)fat_len << bps_sh;
    fs->heap_off = (uint64_t)heap << bps_sh;
    fs->root_cluster = root;
    if (!cluster_ok(fs, root))
        return GC_FAT_ECORRUPT;
    return 0;
}

static int parse_bpb(gc_fat_t *fs, const uint8_t *b)
{
    if (b[0] != 0xEB && b[0] != 0xE9)
        return GC_FAT_EUNSUP;

    uint32_t bps = rd16(b + 11), spc = b[13], rsvd = rd16(b + 14), nfats = b[16];
    uint32_t root_ent = rd16(b + 17), fat16 = rd16(b + 22);
    uint32_t tot = rd16(b + 19) ? rd16(b + 19) : gc_rd32(b + 32);
    uint32_t fatsz = fat16 ? fat16 : gc_rd32(b + 36);

    if ((bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) || !spc || (spc & (spc - 1)) ||
        !rsvd || !nfats || nfats > 4 || !tot || !fatsz)
        return GC_FAT_EUNSUP;

    uint64_t root_secs = ((uint64_t)root_ent * 32 + bps - 1) / bps;
    uint64_t meta = (uint64_t)rsvd + (uint64_t)nfats * fatsz + root_secs;
    if (tot <= meta)
        return GC_FAT_ECORRUPT;
    uint64_t ncl = (tot - meta) / spc;
    uint64_t fat_bytes = (uint64_t)fatsz * bps, need;
    unsigned active = 0;

    if (ncl < 4085) {
        fs->type = GC_FAT_12;
        need = ((ncl + 2) * 3 + 1) / 2;
    } else if (ncl < 65525) {
        fs->type = GC_FAT_16;
        need = (ncl + 2) * 2;
    } else {
        fs->type = GC_FAT_32;
        need = (ncl + 2) * 4;
        if (ncl > 0x0FFFFFF5)
            return GC_FAT_ECORRUPT;
    }
    if (!ncl || need > fat_bytes)
        return GC_FAT_ECORRUPT;

    if (fs->type == GC_FAT_32) {
        uint16_t ext = rd16(b + 40);
        if (fat16 || root_ent || rd16(b + 42) != 0)
            return GC_FAT_ECORRUPT;
        if (ext & 0x80) { /* mirroring disabled: only the active FAT is valid */
            active = ext & 0x0F;
            if (active >= nfats)
                return GC_FAT_ECORRUPT;
        }
        fs->root_cluster = gc_rd32(b + 44) & 0x0FFFFFFF;
    } else if (!root_ent) {
        return GC_FAT_ECORRUPT;
    }

    fs->cluster_bytes = bps * spc;
    fs->cluster_count = (uint32_t)ncl;
    fs->fat_off = ((uint64_t)rsvd + (uint64_t)active * fatsz) * bps;
    fs->root_off = ((uint64_t)rsvd + (uint64_t)nfats * fatsz) * bps;
    fs->root_bytes = (uint64_t)root_ent * 32;
    fs->heap_off = meta * bps;
    if (fs->type == GC_FAT_32 && !cluster_ok(fs, fs->root_cluster))
        return GC_FAT_ECORRUPT;
    return 0;
}

static int try_volume(gc_fat_t *fs, uint64_t lba)
{
    gc_bdev_t dev = fs->dev;
    int rc;

    memset(fs, 0, sizeof *fs);
    fs->dev = dev;
    rc = cache_load(fs, &fs->dir_cache, lba);
    if (rc)
        return rc;
    fs->part_lba = lba;
    const uint8_t *b = fs->dir_cache.buf;
    rc = memcmp(b + 3, "EXFAT   ", 8) == 0 ? parse_exfat(fs, b) : parse_bpb(fs, b);
    if (rc)
        fs->type = GC_FAT_NONE;
    return rc;
}

int gc_fat_mount(gc_fat_t *fs, const gc_bdev_t *dev)
{
    uint8_t mbr[66];
    int rc;

    if (!fs)
        return GC_FAT_EINVAL;
    memset(fs, 0, sizeof *fs);
    if (!dev || !dev->read)
        return GC_FAT_EINVAL;
    fs->dev = *dev;

    rc = try_volume(fs, 0);
    if (rc == 0 || rc == GC_FAT_EIO)
        goto out;

    /* Not a volume boot sector: try it as an MBR. */
    memcpy(mbr, fs->dir_cache.buf + 446, sizeof mbr);
    rc = GC_FAT_EUNSUP;
    if (mbr[64] != 0x55 || mbr[65] != 0xAA)
        goto out;
    for (int i = 0; i < 4; i++) {
        const uint8_t *p = mbr + 16 * i;
        uint8_t type = p[4];
        uint32_t start = gc_rd32(p + 8);
        /* skip empty, extended and GPT-protective entries */
        if (!type || !start || type == 0x05 || type == 0x0F || type == 0x85 || type == 0xEE)
            continue;
        rc = try_volume(fs, start);
        if (rc == 0 || rc == GC_FAT_EIO)
            goto out;
    }
    rc = GC_FAT_EUNSUP;
out:
    if (rc) {
        memset(fs, 0, sizeof *fs);
        return rc;
    }
    return 0;
}

void gc_fat_unmount(gc_fat_t *fs)
{
    if (fs)
        memset(fs, 0, sizeof *fs);
}

int gc_fat_stat(gc_fat_t *fs, const char *path, uint64_t *size)
{
    node_t n;
    uint64_t nc;
    int rc;

    if (!size)
        return GC_FAT_EINVAL;
    rc = open_file(fs, path, &n, &nc);
    if (rc)
        return rc;
    *size = n.size;
    return 0;
}

int gc_fat_read(gc_fat_t *fs, const char *path, uint64_t off, void *buf, size_t len)
{
    node_t n;
    uint64_t nc;
    uint8_t *d = (uint8_t *)buf;
    int rc;

    if (!buf && len)
        return GC_FAT_EINVAL;
    rc = open_file(fs, path, &n, &nc);
    if (rc)
        return rc;
    if (off > n.size || len > n.size - off)
        return GC_FAT_EINVAL;
    if (!len)
        return 0;

    /* exFAT: bytes past ValidDataLength are defined as zero. */
    uint64_t end = off + len, dend = end < n.vdl ? end : n.vdl;
    if (dend < end) {
        uint64_t z = off > dend ? off : dend;
        memset(d + (z - off), 0, (size_t)(end - z));
    }
    if (off >= dend)
        return 0;
    uint64_t left = dend - off;

    const uint32_t cb = fs->cluster_bytes;
    walk_t w;
    walk_init(&w, n.first, n.contig);
    for (uint64_t target = off / cb; w.idx < target;) {
        rc = walk_step(fs, &w);
        if (rc <= 0)
            return rc ? rc : GC_FAT_ECORRUPT;
    }

    uint64_t in = off % cb;
    for (;;) {
        /* Coalesce physically adjacent clusters into one device read. */
        uint32_t start = w.cur;
        uint64_t span = cb - in, k = 1;
        while (span < left) {
            rc = walk_step(fs, &w);
            if (rc <= 0)
                return rc ? rc : GC_FAT_ECORRUPT;
            if ((uint64_t)w.cur != start + k)
                break;
            span += cb;
            k++;
        }
        uint64_t take = span < left ? span : left;
        rc = vol_read(fs, &fs->dir_cache, cluster_off(fs, start) + in, d, (size_t)take);
        if (rc)
            return rc;
        d += take;
        left -= take;
        in = 0;
        if (!left)
            return 0;
        /* w.cur already holds the first cluster of the next extent */
    }
}

int gc_fat_runs(gc_fat_t *fs, const char *path, gc_run_t *runs, size_t max_runs, size_t *out_n)
{
    node_t n;
    uint64_t nc;
    size_t cnt = 0;
    int rc;

    if (!out_n)
        return GC_FAT_EINVAL;
    *out_n = 0;
    if (!runs && max_runs)
        return GC_FAT_EINVAL;
    rc = open_file(fs, path, &n, &nc);
    if (rc)
        return rc;
    if (!n.size)
        return 0;
    if (n.vdl < n.size)
        return GC_FAT_EUNSUP;

    uint64_t secs_left = n.size / GC_SECTOR_SIZE + (n.size % GC_SECTOR_SIZE != 0);
    const uint64_t per_cl = fs->cluster_bytes / GC_SECTOR_SIZE;

    if (n.contig) {
        if (!max_runs)
            return GC_FAT_EOVERFLOW;
        runs[0].sd_sector = fs->part_lba + cluster_off(fs, n.first) / GC_SECTOR_SIZE;
        runs[0].count = secs_left;
        *out_n = 1;
        return 0;
    }

    /* Walk the entire chain to its end-of-chain marker so loops, free/bad
     * links and short chains are rejected, emitting extents for the clusters
     * that hold file data. */
    walk_t w;
    walk_init(&w, n.first, 0);
    for (;;) {
        if (w.idx < nc) {
            uint64_t s = fs->part_lba + cluster_off(fs, w.cur) / GC_SECTOR_SIZE;
            uint64_t c = secs_left < per_cl ? secs_left : per_cl;
            secs_left -= c;
            if (cnt && runs[cnt - 1].sd_sector + runs[cnt - 1].count == s) {
                runs[cnt - 1].count += c;
            } else {
                if (cnt == max_runs)
                    return GC_FAT_EOVERFLOW;
                runs[cnt].sd_sector = s;
                runs[cnt].count = c;
                cnt++;
            }
        }
        rc = walk_step(fs, &w);
        if (rc < 0)
            return rc;
        if (rc == 0)
            break;
    }
    if ((uint64_t)w.idx + 1 < nc)
        return GC_FAT_ECORRUPT;
    *out_n = cnt;
    return 0;
}
