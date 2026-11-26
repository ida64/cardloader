/* fat.h - read-only FAT12/FAT16/FAT32/exFAT reader over a gc_bdev_t.
 *
 * The volume is found either at sector 0 (bare boot sector) or through the
 * first MBR partition entry whose start LBA holds a recognisable boot sector.
 * All device I/O is in absolute 512-byte sectors; volume sector sizes of
 * 512..4096 bytes and any power-of-two cluster size are translated as
 *   absolute = part_lba + volume_byte_offset / 512.
 *
 * Paths are '/'-separated, relative to the root (a leading '/' is tolerated),
 * matched ASCII-case-insensitively against long (VFAT LFN / exFAT) names and
 * FAT 8.3 short names. No allocation, no stdio: everything lives in gc_fat_t.
 */
#ifndef GC_FAT_H
#define GC_FAT_H

#include "gc.h"

/* Error codes (all negative). GC_FAT_EOVERFLOW is -1 by contract. */
#define GC_FAT_EOVERFLOW (-1) /* gc_fat_runs: more runs than max_runs     */
#define GC_FAT_EIO       (-2) /* block device read failed                  */
#define GC_FAT_ENOENT    (-3) /* path component not found                  */
#define GC_FAT_ECORRUPT  (-4) /* bad BPB, bad/looping/short cluster chain  */
#define GC_FAT_EINVAL    (-5) /* bad argument, read outside the file       */
#define GC_FAT_ENOTFILE  (-6) /* target is a directory / walk through file */
#define GC_FAT_EUNSUP    (-7) /* no FAT volume found; exFAT runs past VDL   */

enum { GC_FAT_NONE = 0, GC_FAT_12, GC_FAT_16, GC_FAT_32, GC_FAT_EX };

/* Longest name: 255 UTF-16 units (VFAT: 20 LFN entries x 13). */
#define GC_FAT_NAME16_MAX 260

typedef struct {
    uint64_t lba;   /* absolute 512-byte sector held in buf */
    int valid;
    uint8_t buf[GC_SECTOR_SIZE];
} gc_fat_cache_t;

typedef struct {
    gc_bdev_t dev;
    int type;                /* GC_FAT_* */
    uint64_t part_lba;       /* volume start, absolute 512-byte sectors */
    uint32_t cluster_bytes;
    uint32_t cluster_count;  /* valid clusters are 2..cluster_count+1 */
    uint32_t root_cluster;   /* FAT32 / exFAT */
    uint64_t fat_off;        /* bytes from volume start: active FAT */
    uint64_t heap_off;       /* bytes from volume start: cluster 2 */
    uint64_t root_off;       /* FAT12/16 fixed root: bytes from volume start */
    uint64_t root_bytes;     /* FAT12/16 fixed root size */

    gc_fat_cache_t fat_cache; /* FAT sectors */
    gc_fat_cache_t dir_cache; /* directory entries / unaligned data edges */
    uint16_t name16[GC_FAT_NAME16_MAX];
    char name8[GC_FAT_NAME16_MAX * 3 + 1];
} gc_fat_t;

int  gc_fat_mount(gc_fat_t *fs, const gc_bdev_t *dev);
void gc_fat_unmount(gc_fat_t *fs);

/* Size of a regular file. */
int  gc_fat_stat(gc_fat_t *fs, const char *path, uint64_t *size);

/* Read exactly len bytes at off; off+len beyond EOF is an error.
 * exFAT bytes between ValidDataLength and DataLength read as zero. */
int  gc_fat_read(gc_fat_t *fs, const char *path, uint64_t off, void *buf, size_t len);

/* Map a regular file to merged contiguous extents of absolute 512-byte
 * sectors covering ceil(size/512) sectors in file order. The whole cluster
 * chain is validated (EOC within cluster_count, no loop, long enough).
 * Zero-length file: *out_n = 0, returns 0. More than max_runs extents:
 * GC_FAT_EOVERFLOW (-1). exFAT files with ValidDataLength < DataLength cannot
 * be expressed as raw extents and return GC_FAT_EUNSUP. */
int  gc_fat_runs(gc_fat_t *fs, const char *path, gc_run_t *runs, size_t max_runs, size_t *out_n);

#endif /* GC_FAT_H */
