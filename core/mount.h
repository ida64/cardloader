/* mount.h - control plane: request a mount, mirror it as card presence.
 *
 * Only the shared state is modelled here. The platform supplies one callback
 * that raises a card-detect interrupt (pad 0x93, GPIO_INT_LVL at 0x6000D460
 * on hardware); everything else is deterministic and host-testable.
 */
#ifndef GC_MOUNT_H
#define GC_MOUNT_H

#include "gc.h"

#define GC_MOUNT_TICKS 10          /* 10 x 50 ms */
#define GC_STATUS_PENDING  0
#define GC_STATUS_MOUNTED  256
#define GC_STATUS_FAILED  (-1)

typedef enum {
    GC_MOUNT_IDLE = 0,
    GC_MOUNT_PENDING,
    GC_MOUNT_MOUNTED,
    GC_MOUNT_FAILED,
} gc_mount_status_t;

typedef void (*gc_pulse_fn)(void *ctx);

typedef struct {
    gc_mount_status_t status;
    int countdown;
    bool insert_pulsed;
    char path[256];
    gc_pulse_fn pulse;
    void *pulse_ctx;
} gc_mount_t;

void gc_mount_init(gc_mount_t *m, gc_pulse_fn pulse, void *ctx);

/* 0 accepted, -1 rejected (physical card present or bad path). Emits the
 * removal pulse. */
int gc_mount_request(gc_mount_t *m, const char *path, bool physical_present);

/* One 50 ms tick. Returns 1 when it emitted the insertion pulse. */
int gc_mount_tick(gc_mount_t *m);

/* The emulator reports the first page read's outcome. */
void gc_mount_result(gc_mount_t *m, bool ok);

/* FS's presence predicate: physical line wins; during the countdown the
 * card reads as removed; otherwise the image path defines insertion. */
bool gc_card_present(const gc_mount_t *m, bool gpio_line_low);

/* IPC status value: 0 pending, 256 mounted, -1 failed/idle. */
int gc_mount_code(const gc_mount_t *m);

#endif /* GC_MOUNT_H */
