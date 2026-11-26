/* xci_view.h - presentation logic for xci service clients (switcher NRO,
 * Tesla overlay): error names, card state, list labels, and the select flow
 * the UI drives (a worker thread runs the IPC, the frame loop polls).
 *
 * Plain C, no libnx: the host tests cover it.
 */
#ifndef XCI_VIEW_H
#define XCI_VIEW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "xci_ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* "Busy", "GameCardInUse", ... for module-505 results; NULL otherwise. */
const char *xci_error_name(uint32_t rc);
/* One-line explanation for module-505 results; NULL otherwise. */
const char *xci_error_hint(uint32_t rc);
/* "Name: hint" for service errors, "error 0x..." for anything else. */
void xci_error_describe(uint32_t rc, char *out, size_t n);

/* hh_window.h HH_STAGE_* as text. */
const char *xci_stage_name(uint32_t stage);

typedef enum {
    XCI_CARD_UNKNOWN = 0, /* hook has not mapped the window yet */
    XCI_CARD_NONE,        /* no image: card out */
    XCI_CARD_REMOVING,    /* swap: FS is being shown a removal */
    XCI_CARD_INSERTING,   /* swap: re-inserting, or inserted and FS not reading yet */
    XCI_CARD_MOUNTED,     /* FS reads the card */
    XCI_CARD_FAILED,      /* image rejected or swap timed out */
} xci_card_t;

xci_card_t xci_card_state(const XciStatus *st);
/* "removing", "inserting", "mounted", "no card", "failed", "starting". */
const char *xci_card_text(xci_card_t card);

/* "7.45 GiB" / "68.0 MiB" / "512 KiB". */
void xci_format_size(uint64_t size, char *out, size_t n);
/* List row: label "* name" (current) or "name"; value "2 parts  7.45 GiB". */
void xci_entry_label(const XciImageEntry *e, char *out, size_t n);
void xci_entry_value(const XciImageEntry *e, char *out, size_t n);
/* Index of the entry flagged current, or -1. */
int xci_current_index(const XciImageEntry *entries, uint32_t count);

/* Display title: the name without ".xci" ("digimon.xci" -> "digimon"). Also
 * the base name cover art and cached metadata are stored under. */
void xci_entry_title(const XciImageEntry *e, char *out, size_t n);
/* Where the image lives: "sdmc:/lib/digimon.xc0 + .xc1", "sdmc:/lib/a.xci". */
void xci_entry_location(const char *library, const XciImageEntry *e, char *out, size_t n);
/* "Location, Size" line under the title. */
void xci_entry_subtitle(const char *library, const XciImageEntry *e, char *out, size_t n);

/* Horizontal carousel: index of the first tile to show (as a float, so the
 * caller can animate towards it) that keeps `selected` fully visible with
 * `visible` whole tiles on screen. Moves only when the selection would leave
 * the view, and never scrolls past the last full page. */
float xci_carousel_first(uint32_t count, uint32_t selected, uint32_t visible, float first);

typedef enum {
    XCI_SEL_IDLE = 0,
    XCI_SEL_RUNNING,  /* worker is inside SelectImage* */
    XCI_SEL_SWAPPING, /* accepted; waiting for the swap to finish */
    XCI_SEL_DONE,
    XCI_SEL_FAILED,   /* refused or the swap failed; UI fully usable */
} xci_sel_phase_t;

typedef struct {
    xci_sel_phase_t phase;
    uint32_t result;       /* last select's result */
    uint32_t gen;          /* swap generation the select produced */
    char name[XCI_NAME_MAX];
    char message[160];
} xci_sel_t;

void xci_sel_init(xci_sel_t *s);
/* A new select may start: nothing running and no swap pending. */
bool xci_sel_can_start(const xci_sel_t *s);
/* Frame loop: the worker is about to call SelectImage* for name. */
void xci_sel_start(xci_sel_t *s, const char *name);
/* Frame loop, after the worker finished: its result and a status read
 * taken after it returned. */
void xci_sel_finish(xci_sel_t *s, uint32_t result, const XciStatus *st);
/* Frame loop, every status poll. */
void xci_sel_poll(xci_sel_t *s, const XciStatus *st);

#ifdef __cplusplus
}
#endif

#endif /* XCI_VIEW_H */
