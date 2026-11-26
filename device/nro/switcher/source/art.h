/* art.h - what a tile shows: cover art and the game's own title.
 *
 * Lookup for an image named <base> (xci_entry_title):
 *   1. <library>/<base>.jpg or .png    cover art the user put next to it
 *   2. ART_CACHE/<base>.jpg, .txt      icon and title read from the image
 *                                      file itself (art_extract)
 *   3. generated tile and the file name
 *
 * (2) needs no game launch or insertion: art_extract decrypts the image's
 * Control NCA with keys the system derives at runtime (keys.h).
 */
#ifndef ART_H
#define ART_H

#include <stdbool.h>
#include <stddef.h>
#include <SDL.h>

#include "keys.h"
#include "xci_ipc.h"

#define ART_CACHE "sdmc:/switch/CardLoader/.cache/"

/* Cover art as a surface (caller frees), or NULL. */
SDL_Surface *art_load(const char *library, const char *base);

/* Cached game title, or false. */
bool art_load_title(const char *base, char *out, size_t n);

/* Reads the game's icon and title from the image file(s) of e in library
 * and caches them under base. Blocking (SD reads and writes, spl): run off
 * the frame loop. 0, or a GC_NCA_ERR_* code. */
int art_extract(keys_t *keys, const char *library, const XciImageEntry *e, const char *base);

#endif /* ART_H */
