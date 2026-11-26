#include "xci.h"

#define HFS0_HDR 0x10
#define HFS0_ENT 0x40

int gc_hfs0_parse(gc_xci_t *x, uint64_t off, uint64_t size,
                  gc_hfs0_t *out, gc_hfs0_entry_t *store, size_t cap)
{
    uint8_t hdr[HFS0_HDR];
    if (gc_image_read(x->img, off, hdr, sizeof(hdr)))
        return -1;
    if (memcmp(hdr, "HFS0", 4) != 0)
        return -1;

    uint32_t count = gc_rd32(hdr + 4);
    uint32_t strsize = gc_rd32(hdr + 8);
    if (count > cap || count > 4096)
        return -1;

    size_t table = HFS0_HDR + (size_t)count * HFS0_ENT;
    size_t total = table + strsize;
    if (total > size || total > 0x10000)
        return -1;

    uint8_t buf[0x10000];
    if (gc_image_read(x->img, off, buf, total))
        return -1;
    const uint8_t *strtab = buf + table;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = buf + HFS0_HDR + (size_t)i * HFS0_ENT;
        gc_hfs0_entry_t *o = &store[i];
        memset(o, 0, sizeof(*o));
        uint64_t rel = total + gc_rd64(e + 0);
        o->off = off + rel;
        o->size = gc_rd64(e + 8);
        uint32_t name_off = gc_rd32(e + 0x10);
        o->hashed_size = gc_rd32(e + 0x14);
        memcpy(o->hash, e + 0x20, 32);
        if (name_off < strsize) {
            size_t n = 0;
            while (name_off + n < strsize && strtab[name_off + n] && n + 1 < sizeof(o->name)) {
                o->name[n] = (char)strtab[name_off + n];
                n++;
            }
            o->name[n] = 0;
        }
        if (rel > size || o->size > size - rel)
            return -1;
    }
    out->count = count;
    out->entries = store;
    return 0;
}

int gc_xci_open(gc_xci_t *x, gc_image_t *img)
{
    if (!x || !img)
        return -1;
    memset(x, 0, sizeof(*x));
    x->img = img;
    /* A dump starts with the CardHeader (HEAD at 0x100); the synthetic
     * full-card image keeps a 0x1000 CardKeyArea in front of it. Partition
     * offsets are image offsets in both. */
    if (gc_image_read(img, 0, x->header, sizeof(x->header)) ||
        memcmp(x->header + 0x100, "HEAD", 4) != 0) {
        if (gc_image_read(img, 0x1000, x->header, sizeof(x->header)) ||
            memcmp(x->header + 0x100, "HEAD", 4) != 0)
            return -1;
    }
    x->pfs_off = gc_rd64(x->header + 0x130);
    x->pfs_size = gc_rd64(x->header + 0x138);
    if (x->pfs_off == 0 || x->pfs_size == 0)
        return -1;
    return 0;
}

int gc_xci_root(gc_xci_t *x, gc_hfs0_t *out, gc_hfs0_entry_t *store, size_t cap)
{
    /* 0x138 is the size of the root header alone (what its hash covers).
     * The partitions it lists may end past a trimmed dump's last byte, so
     * their extents are not checked against the image size; reads are. */
    return gc_hfs0_parse(x, x->pfs_off, UINT64_MAX - x->pfs_off, out, store, cap);
}

int gc_xci_partition(gc_xci_t *x, const char *name,
                     gc_hfs0_t *out, gc_hfs0_entry_t *store, size_t cap)
{
    gc_hfs0_entry_t root_store[8];
    gc_hfs0_t root;
    if (gc_xci_root(x, &root, root_store, 8))
        return -1;
    for (uint32_t i = 0; i < root.count; i++) {
        if (strcmp(root.entries[i].name, name) == 0)
            return gc_hfs0_parse(x, root.entries[i].off, root.entries[i].size,
                                 out, store, cap);
    }
    return -1;
}
