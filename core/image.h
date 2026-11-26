/* image.h - a file (XCI) described as a list of contiguous SD extents. */
#ifndef GC_IMAGE_H
#define GC_IMAGE_H

#include "gc.h"

typedef struct {
    gc_bdev_t dev;
    gc_run_t runs[GC_MAX_RUNS];
    size_t nruns;
    uint64_t size; /* logical bytes */
} gc_image_t;

int gc_image_init(gc_image_t *img, const gc_bdev_t *dev,
                  const gc_run_t *runs, size_t nruns, uint64_t size);
int gc_image_read(gc_image_t *img, uint64_t off, void *buf, size_t len);

#endif /* GC_IMAGE_H */
