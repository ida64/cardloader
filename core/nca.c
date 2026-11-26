/* nca.c - see nca.h. Layouts: switchbrew.org/wiki/NCA, /wiki/RomFS,
 * /wiki/NACP. */
#include "nca.h"
#include "crypto.h"

#include <stdlib.h>

#define NCA_HDR_SIZE   0xC00
#define NCA_SECTOR     0x200
#define NCA_TYPE_CONTROL 2
#define FS_ROMFS       0
#define HASH_IVFC      3
#define ENC_NONE       1
#define ENC_CTR        3
#define CHUNK          0x4000
#define META_MAX       0x40000
#define NACP_SIZE      0x4000

void gc_nca_tweak(uint64_t sector, uint8_t out[16])
{
    memset(out, 0, 16);
    for (int i = 0; i < 8; i++)
        out[15 - i] = (uint8_t)(sector >> (8 * i));
}

static int read_header(gc_xci_t *x, uint64_t off, const gc_nca_keys_t *k, uint8_t h[NCA_HDR_SIZE])
{
    if (gc_image_read(x->img, off, h, NCA_HDR_SIZE))
        return GC_NCA_ERR_IO;
    for (uint64_t s = 0; s < NCA_HDR_SIZE / NCA_SECTOR; s++) {
        uint8_t tweak[16];
        gc_nca_tweak(s, tweak);
        gc_aes128_xts(k->header_key, tweak, h + s * NCA_SECTOR, NCA_SECTOR, false);
    }
    return memcmp(h + 0x200, "NCA3", 4) == 0 ? 0 : GC_NCA_ERR_FORMAT;
}

/* One AES-CTR section of an NCA. */
typedef struct {
    gc_xci_t *x;
    uint64_t nca;        /* image offset of the NCA */
    bool encrypted;
    uint8_t key[16];
    uint8_t upper[8];    /* counter bytes 0..7 */
} section_t;

static int section_read(const section_t *s, uint64_t off, uint8_t *buf, size_t n)
{
    uint8_t chunk[CHUNK];
    while (n > 0) {
        const uint64_t base = off & ~(uint64_t)15;
        const size_t skip = (size_t)(off - base);
        size_t take = CHUNK - skip;
        if (take > n)
            take = n;
        const size_t len = (skip + take + 15) & ~(size_t)15;
        if (gc_image_read(s->x->img, s->nca + base, chunk, len))
            return GC_NCA_ERR_IO;
        if (s->encrypted) {
            uint8_t ctr[16];
            memcpy(ctr, s->upper, 8);
            for (int i = 0; i < 8; i++)
                ctr[15 - i] = (uint8_t)((base >> 4) >> (8 * i));
            gc_aes128_ctr(s->key, ctr, chunk, chunk, len);
        }
        memcpy(buf, chunk + skip, take);
        buf += take;
        off += take;
        n -= take;
    }
    return 0;
}

static bool is_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return false;
    return true;
}

/* Sets up section 0 (the RomFS) of a decrypted header; returns the image
 * offset-independent RomFS start (NCA-relative). */
static int open_romfs(gc_xci_t *x, uint64_t nca, const uint8_t *h, const gc_nca_keys_t *k,
                      section_t *s, uint64_t *romfs)
{
    const uint8_t *fs = h + 0x400;
    if (fs[2] != FS_ROMFS || fs[3] != HASH_IVFC || memcmp(fs + 8, "IVFC", 4) != 0)
        return GC_NCA_ERR_FORMAT;
    const uint64_t start = (uint64_t)gc_rd32(h + 0x240) * NCA_SECTOR;
    const uint64_t level5 = gc_rd64(fs + 8 + 0x10 + 5 * 0x18);
    memset(s, 0, sizeof(*s));
    s->x = x;
    s->nca = nca;
    if (fs[4] == ENC_CTR) {
        const uint8_t gen = h[0x206] > h[0x220] ? h[0x206] : h[0x220];
        if (h[0x207] != 0 || k->unwrap(k->ctx, gen, h + 0x300 + 2 * 16, s->key) != 0)
            return GC_NCA_ERR_KEY;
        for (int i = 0; i < 8; i++)
            s->upper[i] = fs[0x140 + 7 - i];
        s->encrypted = true;
    } else if (fs[4] != ENC_NONE) {
        return GC_NCA_ERR_FORMAT;
    }
    *romfs = start + level5;
    return 0;
}

/* Finds a root file of a RomFS by exact name, or by prefix when prefix is
 * true (first match). */
static int romfs_find(uint64_t romfs, const uint8_t *hdr, const uint8_t *meta, size_t meta_size,
                      const char *name, bool prefix, uint64_t *off, uint64_t *size)
{
    const size_t want = strlen(name);
    for (size_t p = 0; p + 0x20 <= meta_size;) {
        const uint8_t *e = meta + p;
        const uint32_t len = gc_rd32(e + 0x1C);
        if (p + 0x20 + len > meta_size)
            break;
        const char *n = (const char *)e + 0x20;
        if ((prefix && len >= want && memcmp(n, name, want) == 0) ||
            (!prefix && len == want && memcmp(n, name, want) == 0)) {
            *off = romfs + gc_rd64(hdr + 0x48) + gc_rd64(e + 0x8);
            *size = gc_rd64(e + 0x10);
            return 0;
        }
        p += 0x20 + ((len + 3u) & ~3u);
    }
    return -1;
}

static void copy_text(char *dst, size_t n, const uint8_t *src, size_t max)
{
    size_t i = 0;
    for (; i + 1 < n && i < max && src[i]; i++)
        dst[i] = (char)src[i];
    dst[i] = 0;
}

static int read_control(gc_xci_t *x, uint64_t nca, const uint8_t *h, const gc_nca_keys_t *k,
                        gc_control_t *out, uint8_t *icon, size_t icon_cap)
{
    section_t s;
    uint64_t romfs;
    int rc = open_romfs(x, nca, h, k, &s, &romfs);
    if (rc)
        return rc;
    uint8_t hdr[0x50];
    if (section_read(&s, romfs, hdr, sizeof(hdr)) || gc_rd64(hdr) != 0x50)
        return GC_NCA_ERR_FORMAT;
    const uint64_t meta_off = gc_rd64(hdr + 0x38), meta_size = gc_rd64(hdr + 0x40);
    if (meta_size == 0 || meta_size > META_MAX)
        return GC_NCA_ERR_FORMAT;
    uint8_t *meta = malloc((size_t)meta_size);
    uint8_t *nacp = malloc(NACP_SIZE);
    rc = GC_NCA_ERR_FORMAT;
    uint64_t off, size;
    if (!meta || !nacp || section_read(&s, romfs + meta_off, meta, (size_t)meta_size))
        goto done;

    if (romfs_find(romfs, hdr, meta, (size_t)meta_size, "control.nacp", false, &off, &size) ||
        size < NACP_SIZE || section_read(&s, off, nacp, NACP_SIZE))
        goto done;
    /* 16 language entries of name[0x200] + publisher[0x100]; English first. */
    int lang = 0;
    while (lang < 16 && nacp[lang * 0x300] == 0)
        lang++;
    if (lang < 16) {
        copy_text(out->title, sizeof(out->title), nacp + lang * 0x300, 0x200);
        copy_text(out->publisher, sizeof(out->publisher), nacp + lang * 0x300 + 0x200, 0x100);
    }

    rc = GC_NCA_ERR_NO_ICON;
    if (romfs_find(romfs, hdr, meta, (size_t)meta_size, "icon_AmericanEnglish.dat", false, &off, &size) &&
        romfs_find(romfs, hdr, meta, (size_t)meta_size, "icon_", true, &off, &size))
        goto done;
    if (size == 0 || size > icon_cap || section_read(&s, off, icon, (size_t)size))
        goto done;
    out->icon_size = (size_t)size;
    rc = 0;
done:
    free(meta);
    free(nacp);
    return rc;
}

int gc_xci_read_control(gc_xci_t *x, const gc_nca_keys_t *keys, gc_control_t *out,
                        uint8_t *icon, size_t icon_cap)
{
    memset(out, 0, sizeof(*out));
    gc_hfs0_entry_t *store = malloc(sizeof(gc_hfs0_entry_t) * 64);
    uint8_t *h = malloc(NCA_HDR_SIZE);
    int rc = GC_NCA_ERR_NO_SECURE;
    gc_hfs0_t secure;
    if (!store || !h || gc_xci_partition(x, "secure", &secure, store, 64))
        goto done;

    /* The base application's Control NCA (program id ...000); an update's
     * (...800) only if the card carries no base one. */
    int pick = -1;
    rc = GC_NCA_ERR_NO_CONTROL;
    for (uint32_t i = 0; i < secure.count; i++) {
        const char *n = secure.entries[i].name;
        const size_t len = strlen(n);
        if (len < 4 || strcmp(n + len - 4, ".nca") != 0 || secure.entries[i].size < NCA_HDR_SIZE)
            continue;
        if (read_header(x, secure.entries[i].off, keys, h) != 0)
            continue;
        if (h[0x205] != NCA_TYPE_CONTROL || !is_zero(h + 0x230, 16))
            continue;
        const bool base = (gc_rd64(h + 0x210) & 0xFFF) == 0;
        if (pick < 0 || base)
            pick = (int)i;
        if (base)
            break;
    }
    if (pick < 0)
        goto done;
    if ((rc = read_header(x, secure.entries[pick].off, keys, h)) != 0)
        goto done;
    out->program_id = gc_rd64(h + 0x210);
    rc = read_control(x, secure.entries[pick].off, h, keys, out, icon, icon_cap);
done:
    free(store);
    free(h);
    return rc;
}

/* SHA-256 of the sources (the values are taken from memory at runtime). */
static const uint8_t HASH_HEADER_KEK[32] = {
    0x18, 0x88, 0xca, 0xed, 0x55, 0x51, 0xb3, 0xed, 0xe0, 0x14, 0x99, 0xe8, 0x7c, 0xe0, 0xd8, 0x68,
    0x27, 0xf8, 0x08, 0x20, 0xef, 0xb2, 0x75, 0x92, 0x10, 0x55, 0xaa, 0x4e, 0x2a, 0xbd, 0xff, 0xc2,
};
static const uint8_t HASH_HEADER_KEY[32] = {
    0x8f, 0x78, 0x3e, 0x46, 0x85, 0x2d, 0xf6, 0xbe, 0x0b, 0xa4, 0xe1, 0x92, 0x73, 0xc4, 0xad, 0xba,
    0xee, 0x16, 0x38, 0x00, 0x43, 0xe1, 0xb8, 0xc4, 0x18, 0xc4, 0x08, 0x9a, 0x8b, 0xd6, 0x4a, 0xa6,
};
static const uint8_t HASH_KAEK_APP[32] = {
    0x04, 0xad, 0x66, 0x14, 0x3c, 0x72, 0x6b, 0x2a, 0x13, 0x9f, 0xb6, 0xb2, 0x11, 0x28, 0xb4, 0x6f,
    0x56, 0xc5, 0x53, 0xb2, 0xb3, 0x88, 0x71, 0x10, 0x30, 0x42, 0x98, 0xd8, 0xd0, 0x09, 0x2d, 0x9e,
};

unsigned gc_find_key_sources(const uint8_t *mem, size_t len, gc_sha256_fn sha, gc_key_sources_t *out)
{
    unsigned found = 0;
    uint8_t d[32];
    for (size_t i = 0; i + 16 <= len && found != GC_KEYSRC_ALL; i++) {
        if ((found & (GC_KEYSRC_HEADER_KEK | GC_KEYSRC_KAEK_APP)) !=
            (GC_KEYSRC_HEADER_KEK | GC_KEYSRC_KAEK_APP)) {
            sha(mem + i, 16, d);
            if (!(found & GC_KEYSRC_HEADER_KEK) && memcmp(d, HASH_HEADER_KEK, 32) == 0) {
                memcpy(out->header_kek_source, mem + i, 16);
                found |= GC_KEYSRC_HEADER_KEK;
            } else if (!(found & GC_KEYSRC_KAEK_APP) && memcmp(d, HASH_KAEK_APP, 32) == 0) {
                memcpy(out->key_area_key_application_source, mem + i, 16);
                found |= GC_KEYSRC_KAEK_APP;
            }
        }
        if (!(found & GC_KEYSRC_HEADER_KEY) && i + 32 <= len) {
            sha(mem + i, 32, d);
            if (memcmp(d, HASH_HEADER_KEY, 32) == 0) {
                memcpy(out->header_key_source, mem + i, 32);
                found |= GC_KEYSRC_HEADER_KEY;
            }
        }
    }
    return found;
}
