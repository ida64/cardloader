/* Host demo: mount an XCI image, enumerate HFS0, then drive the Lotus3
 * emulator through a full FS-side card activation and page reads. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sim.h"
#include "crypto.h"
#include "fat.h"

static uint8_t *g_data;
static size_t g_len;

static int mem_read(void *ctx, void *buf, uint64_t sector, uint32_t count)
{
    (void)ctx;
    uint64_t off = sector << GC_SECTOR_SHIFT;
    size_t n = (size_t)count << GC_SECTOR_SHIFT;
    if (off > g_len || n > g_len - off)
        return -1;
    memcpy(buf, g_data + off, n);
    return 0;
}

static uint32_t rng_state = 0x13579bdf;
static void drng(void *ctx, void *buf, size_t len)
{
    (void)ctx;
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        rng_state = rng_state * 1664525u + 1013904223u;
        p[i] = (uint8_t)(rng_state >> 24);
    }
}

static uint8_t *load(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    size_t len = ((size_t)n + GC_SECTOR_SIZE - 1) & ~(size_t)(GC_SECTOR_SIZE - 1);
    uint8_t *p = (uint8_t *)calloc(1, len);
    if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(p);
        return NULL;
    }
    fclose(f);
    *out_len = len;
    return p;
}

static void list_partition(gc_xci_t *xci, const char *name)
{
    gc_hfs0_entry_t store[32];
    gc_hfs0_t fs;
    if (gc_xci_partition(xci, name, &fs, store, 32)) {
        printf("  %-7s absent\n", name);
        return;
    }
    printf("  %-7s %u file(s)\n", name, fs.count);
    for (uint32_t i = 0; i < fs.count; i++) {
        uint8_t magic[4] = {0};
        gc_image_read(xci->img, fs.entries[i].off, magic, 4);
        printf("           %-36s %8llu bytes  %s\n", fs.entries[i].name,
               (unsigned long long)fs.entries[i].size,
               gc_nca_magic_ok(magic) ? "NCA" : "---");
    }
}

int main(int argc, char **argv)
{
    bool raw = false;
    const char *path = "build/game.xci";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--raw") == 0)
            raw = true;
        else
            path = argv[i];
    }
    g_data = load(path, &g_len);
    if (!g_data) {
        fprintf(stderr, "cannot load %s (run `make image` first)\n", path);
        return 1;
    }

    gc_bdev_t dev = {mem_read, NULL};
    gc_image_t img;

    if (g_len >= 0x1200 && memcmp(g_data + 0x1000, "HEAD", 4) == 0) {
        gc_run_t run = {0, g_len >> GC_SECTOR_SHIFT};
        if (gc_image_init(&img, &dev, &run, 1, g_len)) {
            fprintf(stderr, "image init failed\n");
            return 1;
        }
        printf("== source: raw XCI ==\n");
    } else {
        gc_fat_t fs;
        uint64_t sz = 0;
        gc_run_t runs[GC_MAX_RUNS];
        size_t nr = 0;
        if (gc_fat_mount(&fs, &dev)) {
            fprintf(stderr, "not an XCI and no FAT volume at sector 0\n");
            return 1;
        }
        if (gc_fat_stat(&fs, "game.xci", &sz) ||
            gc_fat_runs(&fs, "game.xci", runs, GC_MAX_RUNS, &nr)) {
            fprintf(stderr, "game.xci not found or not mappable\n");
            return 1;
        }
        if (gc_image_init(&img, &dev, runs, nr, sz)) {
            fprintf(stderr, "image init failed\n");
            return 1;
        }
        printf("== source: FAT, game.xci %llu bytes in %zu extent(s) ==\n",
               (unsigned long long)sz, nr);
    }

    gc_xci_t xci;
    if (gc_xci_open(&xci, &img)) {
        fprintf(stderr, "not an XCI (no HEAD at 0x1000)\n");
        return 1;
    }

    printf("== XCI ==\n");
    printf("  image        %llu bytes\n", (unsigned long long)img.size);
    printf("  partition fs 0x%llx size 0x%llx\n",
           (unsigned long long)xci.pfs_off, (unsigned long long)xci.pfs_size);
    printf("  rom area     page 0x%x\n", gc_rd32(xci.header + 0x104));
    printf("  package id   %016llx\n", (unsigned long long)gc_rd64(xci.header + 0x110));
    printf("  rom size     0x%02x\n", xci.header[0x10D]);

    gc_hfs0_entry_t root_store[8];
    gc_hfs0_t root;
    if (gc_xci_root(&xci, &root, root_store, 8)) {
        fprintf(stderr, "root HFS0 parse failed\n");
        return 1;
    }
    printf("== root HFS0 (%u partitions) ==\n", root.count);
    for (uint32_t i = 0; i < root.count; i++)
        list_partition(&xci, root.entries[i].name);

    int rc;
    if (raw) {
        printf("== ASIC executor (raw, FS 22.5.0 boundary) ==\n");
        gc_asic_t asic;
        gc_asic_init(&asic, drng, NULL);
        if (gc_asic_attach(&asic, &img)) {
            fprintf(stderr, "gc_asic_attach failed\n");
            return 1;
        }
        printf("  attached: asic random %02x%02x%02x%02x...\n",
               asic.l3.asic_rand[0], asic.l3.asic_rand[1],
               asic.l3.asic_rand[2], asic.l3.asic_rand[3]);
        rc = fs_handshake_raw(&asic, &xci, true);
    } else {
        printf("== Lotus3 ==\n");
        l3_t l3;
        l3_init(&l3, drng, NULL);
        if (l3_attach(&l3, &img)) {
            fprintf(stderr, "l3_attach failed\n");
            return 1;
        }
        printf("  attached: state=mounted, asic random %02x%02x%02x%02x...\n",
               l3.asic_rand[0], l3.asic_rand[1], l3.asic_rand[2], l3.asic_rand[3]);
        rc = fs_handshake(&l3, &xci, true);
    }

    printf("\n%s\n", rc == 0 ? "PASS: FS-side activation completed, pages served"
                             : "FAIL: see above");
    free(g_data);
    return rc == 0 ? 0 : 1;
}
