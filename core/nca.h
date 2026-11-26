/* nca.h - the game's own icon and title from an XCI: the secure partition's
 * Control NCA, its RomFS, control.nacp and icon_*.dat.
 *
 * No key material lives here or in the repository. The caller supplies the
 * NCA header key and a function that unwraps key-area entries; on the
 * console both come from the system at runtime (spl, with key sources found
 * in FS's memory by gc_find_key_sources), never from a keys file.
 */
#ifndef GC_NCA_H
#define GC_NCA_H

#include "gc.h"
#include "xci.h"

typedef struct {
    uint8_t header_key[32];
    /* Decrypts one 16-byte key-area entry with the application key-area key
     * for the NCA's key generation (the larger of its two fields; master key
     * revision generation - 1, at least 0, as spl/secmon take it). 0 on
     * success. */
    int (*unwrap)(void *ctx, uint8_t generation, const uint8_t in[16], uint8_t out[16]);
    void *ctx;
} gc_nca_keys_t;

typedef struct {
    uint64_t program_id;
    char title[0x201];     /* NACP name, American English first */
    char publisher[0x101];
    size_t icon_size;      /* JPEG bytes written to the caller's buffer */
} gc_control_t;

enum {
    GC_NCA_ERR_IO = -1,
    GC_NCA_ERR_NO_SECURE = -2,  /* no secure partition */
    GC_NCA_ERR_NO_CONTROL = -3, /* no Control NCA we can read */
    GC_NCA_ERR_KEY = -4,        /* key-area unwrap failed */
    GC_NCA_ERR_FORMAT = -5,     /* unexpected NCA / RomFS layout */
    GC_NCA_ERR_NO_ICON = -6,
};

/* Reads the base application's control data. icon: caller buffer of
 * icon_cap bytes (0x20000 holds any icon). 0 or GC_NCA_ERR_*. */
int gc_xci_read_control(gc_xci_t *x, const gc_nca_keys_t *keys, gc_control_t *out,
                        uint8_t *icon, size_t icon_cap);

/* NCA header sector tweak: the sector number, big-endian. */
void gc_nca_tweak(uint64_t sector, uint8_t out[16]);

/* The public seeds FS feeds to spl to derive the header key and the
 * application key-area keys. Found by SHA-256 in a memory dump (FS's
 * read-only data), so their values are not part of this code. */
typedef struct {
    uint8_t header_kek_source[16];
    uint8_t header_key_source[32];
    uint8_t key_area_key_application_source[16];
} gc_key_sources_t;

#define GC_KEYSRC_HEADER_KEK 1u
#define GC_KEYSRC_HEADER_KEY 2u
#define GC_KEYSRC_KAEK_APP   4u
#define GC_KEYSRC_ALL        7u

typedef void (*gc_sha256_fn)(const void *data, size_t len, uint8_t out[32]);

/* Scans mem byte by byte; returns the GC_KEYSRC_* mask of what was found. */
unsigned gc_find_key_sources(const uint8_t *mem, size_t len, gc_sha256_fn sha,
                             gc_key_sources_t *out);

#endif /* GC_NCA_H */
