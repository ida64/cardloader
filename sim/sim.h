#ifndef GC_SIM_H
#define GC_SIM_H

#include "gc.h"
#include "image.h"
#include "lotus3.h"
#include "asic.h"
#include "xci.h"

/* Drives the emulator through FS's exact card-activation sequence:
 * firmware, certs, random exchange, challenges, secure mode, key area,
 * header, then SendCardCommand page reads. Returns 0 if every FS-side
 * check passes. Host only: uses the test SoC private key. */
int fs_handshake(l3_t *l3, gc_xci_t *xci, bool verbose);

/* Same activation, but through the FS 22.5.0 executor boundary
 * (gc_asic_exec): plaintext buffers, no session crypto. */
int fs_handshake_raw(gc_asic_t *a, gc_xci_t *xci, bool verbose);

#endif /* GC_SIM_H */
