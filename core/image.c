#include "image.h"

/* Read n bytes at an absolute byte offset on the device, using a bounce
 * buffer only when the request is not sector aligned. */
static int read_span(const gc_bdev_t *dev, uint64_t byte_off, void *dst, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    uint8_t bounce[4096];
    while (n) {
        uint64_t sec = byte_off >> GC_SECTOR_SHIFT;
        size_t within = (size_t)(byte_off & (GC_SECTOR_SIZE - 1));
        size_t chunk = 4096 - (size_t)(byte_off & 4095);
        if (chunk > n)
            chunk = n;
        if (within == 0 && chunk >= GC_SECTOR_SIZE) {
            size_t direct = chunk & ~(size_t)(GC_SECTOR_SIZE - 1);
            if (gc_bdev_read(dev, d, sec, (uint32_t)(direct >> GC_SECTOR_SHIFT)))
                return -1;
            d += direct;
            byte_off += direct;
            n -= direct;
            continue;
        }
        size_t ssecs = (within + chunk + GC_SECTOR_SIZE - 1) >> GC_SECTOR_SHIFT;
        if (gc_bdev_read(dev, bounce, sec, (uint32_t)ssecs))
            return -1;
        memcpy(d, bounce + within, chunk);
        d += chunk;
        byte_off += chunk;
        n -= chunk;
    }
    return 0;
}

int gc_image_init(gc_image_t *img, const gc_bdev_t *dev,
                  const gc_run_t *runs, size_t nruns, uint64_t size)
{
    if (!img || !dev || !dev->read || nruns > GC_MAX_RUNS)
        return -1;
    memset(img, 0, sizeof(*img));
    img->dev = *dev;
    memcpy(img->runs, runs, nruns * sizeof(runs[0]));
    img->nruns = nruns;
    img->size = size;
    return 0;
}

int gc_image_read(gc_image_t *img, uint64_t off, void *buf, size_t len)
{
    if (!img || !buf)
        return -1;
    if (len > img->size || off > img->size - len)
        return -1;

    uint8_t *d = (uint8_t *)buf;
    uint64_t run_start = 0;
    for (size_t i = 0; i < img->nruns && len; i++) {
        uint64_t bytes = img->runs[i].count << GC_SECTOR_SHIFT;
        if (off >= run_start + bytes) {
            run_start += bytes;
            continue;
        }
        uint64_t within = off - run_start;
        size_t n = (size_t)(bytes - within);
        if (n > len)
            n = len;
        uint64_t byte_off = (img->runs[i].sd_sector << GC_SECTOR_SHIFT) + within;
        if (read_span(&img->dev, byte_off, d, n))
            return -1;
        d += n;
        off += n;
        len -= n;
        run_start += bytes;
    }
    return len ? -1 : 0;
}
