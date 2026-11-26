/* hh_window.h - shared page window between the FS hook and the xci sysmodule.
 *
 * The sysmodule creates a shared memory, returns a copy handle over IPC, and
 * the FS hook maps it at or below HH_WINDOW_VA.  Requests are up to 32 card
 * pages of 4 KiB; the sysmodule reads the XCI parts from SD through fsp-srv
 * and fills the window.
 *
 * Hot swap (sysmodule stages a new image, the hook makes FS see a removal
 * and a re-insertion):
 *   sysmodule  swap_req = n          new image opened, old one still served
 *   hook       stage SWAP_REMOVING   card reads as removed, detector woken
 *   hook       swap_ack = n          FS sampled the removal; no op in flight,
 *                                    old image detached (stage SWAP_DETACHED)
 *   sysmodule  swap_done = n         old files closed, total = new size
 *   hook       stage SWAP_INSERTING  new image attached, insertion countdown
 *   hook       stage SWAP_INSERTED   insertion pulse sent; FS re-activates
 */
#ifndef HH_WINDOW_H
#define HH_WINDOW_H

#include <stdint.h>

#define HH_WINDOW_VA        0x7000000000ULL
#define HH_WINDOW_SIZE      0x21000u
#define HH_WINDOW_PAGE_SIZE 0x1000u
#define HH_WINDOW_DATA_SIZE 0x20000u
#define HH_WINDOW_ERROR     0x80000000u

/* hh_window_t.stage: how far the FS hook got after mapping the window. */
#define HH_STAGE_MAPPED           1u
#define HH_STAGE_EMPTY            2u /* total == 0: the sysmodule has no image */
#define HH_STAGE_ATTACH_FAILED    3u /* image rejected by the ASIC model */
#define HH_STAGE_ARMED            4u /* card reads as inserted */
#define HH_STAGE_WAKE_NO_FS       5u /* FS image did not match 23.5.0 */
#define HH_STAGE_WAKE_NO_DETECTOR 6u /* nn.gc not initialised yet; it samples on init */
#define HH_STAGE_WAKE_NO_EVENT    7u /* detector thread not running yet */
#define HH_STAGE_WAKE_SENT        8u /* detector asked to re-sample */
#define HH_STAGE_SWAP_REMOVING    9u /* swap: card reads as removed, detector woken */
#define HH_STAGE_SWAP_DETACHED   10u /* swap: FS sampled the removal, old image released */
#define HH_STAGE_SWAP_INSERTING  11u /* swap: new image attached, insertion countdown */
#define HH_STAGE_SWAP_INSERTED   12u /* swap: insertion pulse sent */
#define HH_STAGE_SWAP_EMPTY      13u /* swap: new image empty, card stays removed */
#define HH_STAGE_SWAP_TIMEOUT    14u /* swap: sysmodule never completed, card stays removed */
#define HH_STAGE_SWAP_FAILED     15u /* swap: new image rejected by the ASIC model */

/* One ASIC operation as the FS hook served it. */
typedef struct {
    uint8_t op;        /* operation header byte 0 */
    uint8_t mode;      /* 1 host->card, 2 card->host, 0 none */
    uint8_t rc;        /* gc_asic_exec result, 0 ok */
    uint8_t status;    /* status word FS sees (low byte) */
    uint32_t len;      /* payload length the hook used */
    uint32_t pending;  /* emulator's frame length for the op */
    uint8_t hdr[8];    /* operation header bytes 1..8 */
    uint8_t head[8];   /* payload start: received, or served before sealing */
} hh_trace_t;

#define HH_TRACE_LEN 64u /* ring; entry n lives at trace[n % HH_TRACE_LEN] */

typedef struct {
    volatile uint32_t req;        /* incremented by the FS side */
    volatile uint32_t status;     /* req when done, req|ERROR on failure */
    volatile uint32_t card_page;  /* XCI card page (4 KiB units) */
    volatile uint32_t count;      /* pages requested, 1..32 */
    volatile uint64_t total;      /* XCI size in bytes, set by the sysmodule */
    uint8_t data[HH_WINDOW_DATA_SIZE];
    /* Written by the FS hook, logged by the sysmodule. */
    volatile uint32_t stage;          /* HH_STAGE_* */
    volatile uint32_t presence_calls; /* inserted-predicate calls since boot */
    volatile uint32_t presence_hits;  /* of those, answered "inserted" */
    volatile uint32_t exec_count;     /* ASIC operations served since boot */
    volatile uint32_t exec_last;      /* last op | result << 8 */
    /* Every ASIC operation the hook served. Offsets are asserted on both
     * sides (hh_glue.c, xci_main.cpp). */
    volatile uint32_t trace_seq;      /* operations recorded since boot */
    hh_trace_t trace[HH_TRACE_LEN];
    /* Hot swap handshake (see the top of this file). Generations count from
     * 1; equal values mean the step is complete. */
    volatile uint32_t swap_req;   /* sysmodule: generation of the staged image */
    volatile uint32_t swap_ack;   /* hook: old image detached for swap_req */
    volatile uint32_t swap_done;  /* sysmodule: staged image live, total updated */
    volatile int32_t mount_code;  /* hook: 0 inserting, 256 mounted, -1 none/failed */
} hh_window_t;

#endif /* HH_WINDOW_H */
