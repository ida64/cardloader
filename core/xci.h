/* xci.h - CardHeader + HFS0 ("SHA-256 File System") reading.
 *
 * Reference: switchbrew.org/wiki/XCI. Only the plaintext metadata is parsed;
 * NCA payloads are FS's business.
 */
#ifndef GC_XCI_H
#define GC_XCI_H

#include "gc.h"
#include "image.h"

typedef struct {
    char name[96];
    uint64_t off;        /* absolute XCI offset of the file body */
    uint64_t size;       /* file size in bytes */
    uint64_t hashed_size;/* first hashed_size bytes have `hash` */
    uint8_t hash[32];
} gc_hfs0_entry_t;

typedef struct {
    uint32_t count;
    gc_hfs0_entry_t *entries; /* caller storage */
} gc_hfs0_t;

typedef struct {
    gc_image_t *img;
    uint8_t header[GC_HEADER_SIZE]; /* the CardHeader (sig + "HEAD" at 0x100) */
    uint64_t pfs_off;
    uint64_t pfs_size;
} gc_xci_t;

/* Reads and validates the CardHeader: at 0 in a dump, at 0x1000 behind a
 * CardKeyArea. */
int gc_xci_open(gc_xci_t *x, gc_image_t *img);

/* Parses an HFS0 header at absolute offset `off` with `size` available. */
int gc_hfs0_parse(gc_xci_t *x, uint64_t off, uint64_t size,
                  gc_hfs0_t *out, gc_hfs0_entry_t *store, size_t cap);

int gc_xci_root(gc_xci_t *x, gc_hfs0_t *out, gc_hfs0_entry_t *store, size_t cap);

/* Finds a root partition by name (e.g. "secure") and parses it. */
int gc_xci_partition(gc_xci_t *x, const char *name,
                     gc_hfs0_t *out, gc_hfs0_entry_t *store, size_t cap);

static inline bool gc_nca_magic_ok(const uint8_t h[4])
{
    return h[0] == 'N' && h[1] == 'C' && h[2] == 'A';
}

#endif /* GC_XCI_H */
