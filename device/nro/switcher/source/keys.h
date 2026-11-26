/* keys.h - NCA keys obtained from the running system, never from a file.
 *
 * FS keeps the public key *sources* in its read-only data; spl turns them
 * into keys with the console's master keys, which never leave the security
 * engine. So: attach to FS as a debugger just long enough to copy its
 * read-only segments, find the three sources by SHA-256
 * (gc_find_key_sources), then ask spl:
 *
 *   header key      = GenerateAesKey(GenerateAesKek(header_kek_source, 0, 0),
 *                                    header_key_source[0..16] / [16..32])
 *   key-area entry  = GenerateAesKey(GenerateAesKek(kaek_application_source,
 *                                                   generation, 0), entry)
 *
 * which is what FS does for itself. Nothing is written anywhere. Needs the
 * homebrew loader's debug capability (Atmosphère's hbl has force_debug)
 * and kernel debug mode (exosphere.ini debugmode=1, the default).
 */
#ifndef SWITCHER_KEYS_H
#define SWITCHER_KEYS_H

#include <stdbool.h>
#include <switch.h>

#include "nca.h"

#define KEYS_GEN_MAX 32

typedef struct {
    gc_nca_keys_t nca;   /* header key + unwrap through spl */
    u8 kaek_source[16];
    u8 sealed_kek[KEYS_GEN_MAX][16];
    u32 have_kek;        /* bit per generation already in sealed_kek */
    bool spl_open;
    char error[96];      /* why keys_init failed */
} keys_t;

/* Blocking (FS attach, spl IPC): call on a worker thread. While FS is held
 * for the copy, this thread does no file I/O. false: see k->error. */
bool keys_init(keys_t *k);
void keys_exit(keys_t *k);

#endif /* SWITCHER_KEYS_H */
