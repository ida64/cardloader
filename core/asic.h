/* asic.h - the ASIC transaction boundary, matching FS's executor.
 *
 * FS 22.5.0 funnels every Lotus3 operation through sub_1890B0 (23.5.0:
 * sub_18C3B0) with:
 *   (this, uint32_t *status, void *data, size_t len, ..., const void *hdr)
 * where hdr is the 0x40-byte operation header. This adapter is the exact
 * body a detour at that site installs.
 *
 * FS's session crypto straddles that boundary. Host -> device payloads are
 * encrypted inside the executor (sub_18C640), so the detour receives them in
 * plaintext. Device -> host payloads are decrypted after the executor returns,
 * by the op wrapper's copy-out (sub_18B790), so a read served here must be
 * sealed with gc_link_seal() under FS's live session state.
 */
#ifndef GC_ASIC_H
#define GC_ASIC_H

#include "gc.h"
#include "image.h"
#include "lotus3.h"

typedef struct {
    l3_t l3;
} gc_asic_t;

void gc_asic_init(gc_asic_t *a, gc_random_fn rng, void *rng_ctx);
int gc_asic_attach(gc_asic_t *a, gc_image_t *img);
/* Drops the image (card removed): page reads fail until the next attach. */
void gc_asic_detach(gc_asic_t *a);
void gc_asic_set_cert(gc_asic_t *a, const uint8_t *cert, size_t len);

/* Mirrors sub_1890B0: status is written on every path; data is read or
 * written according to the operation. Returns 0 on success. */
int gc_asic_exec(gc_asic_t *a, uint32_t *status, void *data, size_t len,
                 const uint8_t hdr[GC_OP_SIZE]);

/* Material FS holds for the card's replies and the card would know; the hook
 * reads it from FS (FS 23.5.0 addresses in hh_glue.c). */
typedef struct {
    const uint8_t *mac_key;    /* 32-byte HMAC-SHA256 key */
    const uint8_t *mac_salt;   /* 16 bytes appended to every reply MAC */
    const uint8_t *mac_ctr;    /* 16-byte reply counter FS checks next */
    const uint8_t *header_key; /* AES-128 CardInfo key; NULL leaves CardInfo */
} gc_card_secrets_t;

/* Completes the device -> host frame of the operation just executed, before
 * sealing: GetCardHeader (0x0E) gets CardInfo in plaintext and its MAC,
 * the CardKeyArea (0x0F) its MAC (FS 23.5.0 sub_1902C0). Other ops: no-op. */
void gc_asic_authenticate(gc_asic_t *a, uint8_t *frame, size_t len,
                          const gc_card_secrets_t *s);

/* FS's link encryption of a device -> host frame, as sub_18B790 undoes it. */
typedef enum {
    GC_LINK_PLAIN = 0, /* no session yet: FS copies the frame as is */
    GC_LINK_CBC,       /* session key ready: AES-128-CBC, fixed session IV */
    GC_LINK_CTR,       /* secure mode: AES-128-CTR, live big-endian counter */
} gc_link_t;

/* Encrypts buf[0..buf_len) in place so that FS's copy-out yields the
 * plaintext. len is the frame's logical length (FS's request length; it only
 * matters for CBC when it is not a multiple of 16, where FS decrypts the tail
 * block on its own from the IV). iv is the CBC IV or the CTR counter; neither
 * is modified. buf_len must be a multiple of 16 and at least len rounded up. */
void gc_link_seal(gc_link_t mode, const uint8_t key[16], const uint8_t iv[16],
                  uint8_t *buf, size_t buf_len, size_t len);

/* Presence predicate shared with the mount state machine. */
bool gc_asic_present(gc_asic_t *a, bool gpio_line_low);

#endif /* GC_ASIC_H */
