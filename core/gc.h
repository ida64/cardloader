/* gc.h - shared primitives for the gamecard emulator core.
 *
 * Everything below the FS hook is platform independent: it only sees a
 * 512-byte-sector block device. On the console that device is FS's own
 * SDMMC1 read routine; in the host harness it is a file.
 */
#ifndef GC_H
#define GC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define GC_SECTOR_SHIFT 9
#define GC_SECTOR_SIZE  (1u << GC_SECTOR_SHIFT) /* 0x200 */
#define GC_PAGE_SIZE    0x200                   /* gamecard page == sector */
#define GC_OP_SIZE      0x40                    /* Lotus3 operation header */
#define GC_HEADER_SIZE  0x200                   /* XCI CardHeader */
#define GC_KEYAREA_SIZE 0x800                   /* CardKeyArea: 0x200 cert + 0x600 data */

/* One contiguous SD extent, in 512-byte sectors. */
typedef struct {
    uint64_t sd_sector;
    uint64_t count;
} gc_run_t;

/* 512-entry table per spec 6.3. Overflow is a hard mount failure. */
#define GC_MAX_RUNS 512

/* Block device: absolute 512-byte sector reads.
 * Returns 0 on success, negative on error. Buffers are the caller's. */
typedef int (*gc_block_read_fn)(void *ctx, void *buf, uint64_t sector, uint32_t count);

typedef struct {
    gc_block_read_fn read;
    void *ctx;
} gc_bdev_t;

static inline int gc_bdev_read(const gc_bdev_t *d, void *buf, uint64_t sector, uint32_t count)
{
    if (!d || !d->read)
        return -1;
    return d->read(d->ctx, buf, sector, count);
}

/* Platform entropy. Must be a CSPRNG; the session key's only secret input. */
typedef void (*gc_random_fn)(void *ctx, void *buf, size_t len);

static inline uint32_t gc_rd32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint32_t gc_rd32be(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline uint64_t gc_rd64(const void *p)
{
    return (uint64_t)gc_rd32(p) | ((uint64_t)gc_rd32((const uint8_t *)p + 4) << 32);
}

static inline uint64_t gc_rd64be(const void *p)
{
    return ((uint64_t)gc_rd32be(p) << 32) | gc_rd32be((const uint8_t *)p + 4);
}

static inline void gc_wr32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}

static inline void gc_wr32be(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v;
}

#endif /* GC_H */
