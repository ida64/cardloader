/* hh_swap.h - FS-hook side of the shared window: page reads, the lock that
 * keeps an image swap away from an ASIC op in flight, and the hot-swap state
 * machine (handshake in hh_window.h).
 *
 * Plain C over core/: the platform supplies hh_window_pause() and a detector
 * wake; host tests link this file directly.
 */
#ifndef HH_SWAP_H
#define HH_SWAP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "asic.h"
#include "mount.h"
#include "hh_window.h"

/* Timing of a swap, in milliseconds of hh_swap_poll()'s clock. */
#define HH_SWAP_POLL_MS       50u    /* poll period; one gc_mount tick */
#define HH_SWAP_SETTLE_MS     1000u  /* removed state held after FS sampled it */
#define HH_SWAP_REMOVE_MAX_MS 3000u  /* proceed even if FS never sampled */
#define HH_SWAP_DONE_MAX_MS   10000u /* sysmodule silent this long: SWAP_TIMEOUT */

/* Brief sleep between polls of the window; provided by the platform. */
void hh_window_pause(void);

/* Reads image bytes through the sysmodule. 0 on success. */
int hh_window_read(hh_window_t *w, void *buf, uint64_t off, size_t n);

/* Held around every ASIC op and around attach/detach. */
void hh_exec_lock(void);
void hh_exec_unlock(void);

enum { HH_SWAP_IDLE = 0, HH_SWAP_REMOVING, HH_SWAP_DETACHED, HH_SWAP_INSERTING };

typedef struct {
    hh_window_t *w;
    gc_asic_t *asic;
    gc_image_t *img;
    gc_mount_t *mount;
    uint32_t (*wake)(void);   /* wake FS's detector; returns HH_STAGE_WAKE_* */
    volatile bool present;    /* what FS's inserted predicate answers */
    bool attached;
    uint32_t last_wake;
    int state;
    uint32_t target;          /* swap generation being served */
    uint32_t t0;
    uint32_t calls0;          /* presence_calls when the removal was signalled */
} hh_swap_t;

/* Takes over mount's pulse callback: every pulse wakes the detector. */
void hh_swap_init(hh_swap_t *s, gc_asic_t *asic, gc_image_t *img, gc_mount_t *mount,
                  uint32_t (*wake)(void));

/* First mapping of the window: attach w->total's image, arm, wake the
 * detector. Returns the stage reached (HH_STAGE_*), also written to w. */
uint32_t hh_swap_boot(hh_swap_t *s, hh_window_t *w);

/* One step of a pending swap; call every HH_SWAP_POLL_MS with a monotonic
 * millisecond clock. */
void hh_swap_poll(hh_swap_t *s, uint32_t now_ms);

/* Reports an ASIC op's result; the first card command after an insertion
 * completes the mount (gc_mount_result). Caller holds the exec lock. */
void hh_swap_note_op(hh_swap_t *s, uint8_t op, int rc);

#endif /* HH_SWAP_H */
