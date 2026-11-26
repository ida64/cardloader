/* xci_lib.h - sysmodule side of the window, in plain C so the host tests run
 * the same code: the image library (directory scan, names, split parts), page
 * serving, and the sysmodule half of the hot-swap handshake (hh_window.h).
 *
 * Not thread-safe: the sysmodule serialises calls with one mutex.
 */
#ifndef XCI_LIB_H
#define XCI_LIB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hh_window.h"
#include "xci_ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* File access, supplied by the platform. read() may be handed shared memory
 * as the destination; it must bounce if its transport cannot write there. */
typedef struct {
    int (*open)(void *ctx, const char *path, void **file, uint64_t *size);
    void (*close)(void *ctx, void *file);
    int (*read)(void *ctx, void *file, uint64_t off, void *buf, size_t n);
    /* Calls add() for every regular file directly in dir. 0 on success. */
    int (*list)(void *ctx, const char *dir,
                void (*add)(void *cookie, const char *name, uint64_t size), void *cookie);
    void *ctx;
} xci_fs_t;

/* An image reference: path of the .xci file, or of the split base. */
typedef struct {
    char path[XCI_PATH_MAX];
    bool split;
} xci_ref_t;

typedef struct {
    xci_ref_t ref;
    char name[XCI_NAME_MAX]; /* catalog name: last component of ref.path */
    void *part0, *part1;     /* part1 only for split images that have one */
    uint64_t size0, total;
    bool open;
} xci_image_t;

typedef struct {
    XciImageEntry entries[XCI_MAX_IMAGES];
    uint32_t count;
} xci_catalog_t;

typedef struct {
    const xci_fs_t *fs;
    char dir[XCI_PATH_MAX];   /* library directory, ends with '/' */
    xci_image_t cur;          /* image the window describes */
    xci_image_t staged;       /* opened by a select, live once the hook acked */
    uint32_t gen;             /* last swap generation issued */
    uint32_t served;          /* last window request served */
    uint32_t read_failures;
    int read_error;           /* last read() failure code */
} xci_server_t;

/* Resolves a name or path (see xci_ipc.h) against dir. 0 or an XciError_*. */
int xci_resolve(const char *dir, const char *in, xci_ref_t *out);

/* Lists dir's images, sorted by name. 0 or XciError_ListFailed. */
int xci_catalog_scan(const xci_fs_t *fs, const char *dir, xci_catalog_t *cat);

int xci_image_open(const xci_fs_t *fs, const xci_ref_t *ref, xci_image_t *img);
void xci_image_close(const xci_fs_t *fs, xci_image_t *img);
/* Reads within [0, total); 0 on success. */
int xci_image_read(const xci_fs_t *fs, const xci_image_t *img, uint64_t off, void *buf, size_t n);

void xci_server_init(xci_server_t *s, const xci_fs_t *fs, const char *dir);

/* Boot (before the reader runs): the slot starts empty, so the hook reports
 * no card until the first select inserts one. */
void xci_server_boot(xci_server_t *s, hh_window_t *w);

/* Stages an image and starts a swap. Busy while a swap runs; a bad name or
 * an unreadable file fails without touching the current image or the
 * window. 0 or an XciError_*. */
int xci_server_select(xci_server_t *s, hh_window_t *w, const char *name_or_path);

/* Select by position in xci_catalog_scan(dir)'s order. */
int xci_server_select_index(xci_server_t *s, hh_window_t *w, uint32_t index);

/* Reader step: serves one pending page request and completes a swap the hook
 * acknowledged. Returns true if it did either. */
bool xci_server_step(xci_server_t *s, hh_window_t *w);

/* Marks cat's entry for s->cur (or the staged image during a swap). */
void xci_server_mark_current(const xci_server_t *s, xci_catalog_t *cat);

/* Fills an entry for the current (or staged) image; empty name if none. */
void xci_server_current(const xci_server_t *s, XciImageEntry *out);

#ifdef __cplusplus
}
#endif

#endif /* XCI_LIB_H */
