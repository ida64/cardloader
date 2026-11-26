/* hh.h - hook-host payload for FS 22.5.0.
 *
 * This is the code a Loader replacement maps into FS's address space and
 * patches in. It carries no Atmosphère dependency: the loader supplies the
 * FS image, the target addresses and the platform callbacks.
 */
#ifndef HH_H
#define HH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "hh_window.h"

/* Filled in by the loader before FS runs. Lives in the payload's .bss. */
typedef struct {
    uint64_t xci_addr;   /* VA of a memory-loaded XCI inside FS */
    uint64_t xci_size;
    char     path[256];  /* mount path, for status/logging */
} hh_runtime_t;

extern hh_runtime_t hh_runtime;

typedef struct {
    uint32_t executor;        /* 0x1890B0: ASIC transaction executor */
    uint32_t presence;        /* 0x189EE0: card-detect read */
    uint32_t initdata_call;   /* 0x18471C: BL sub_18DFF0 -> MOV W0,#0 */
    uint32_t cert_call;       /* card-certificate RSA verify call -> MOV W0,#0;
                               * 0 = not identified for this build */
    uint32_t bss_base;        /* 0x264000: image base = X0 - this */
} hh_sites_t;

typedef struct {
    const void *exec_target;      /* hh_exec_tramp */
    const void *presence_target;  /* hh_presence_tramp */
} hh_hooks_t;

/* Writes 16-byte absolute detours and the one-instruction InitialData and
 * card-certificate patches. Returns 0 on success, -1 on a null argument or
 * overlapping sites. */
int hh_install(void *fs, const hh_sites_t *sites, const hh_hooks_t *hooks);

void hh_encode_detour(uint8_t out[16], const void *target);
void hh_encode_mov_w0_0(uint8_t out[4]);

extern const hh_sites_t HH_FS_22_5_0;
extern const hh_sites_t HH_FS_23_5_0;

/* Start the private thread that maps the xci sysmodule's shared page window,
 * calls ready(window) on that thread, then poll(window) every
 * HH_SWAP_POLL_MS. Never blocks; a no-op once the thread exists. */
void hh_window_start(void (*ready)(hh_window_t *), void (*poll)(hh_window_t *));

/* Monotonic milliseconds (system tick). */
uint32_t hh_now_ms(void);

#endif /* HH_H */
