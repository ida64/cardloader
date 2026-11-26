/* crypto.h - SHA-256, HMAC-SHA256, AES-128 (CBC/CTR), RSA-2048 OAEP encrypt.
 *
 * Only the RSA *public* operation and AES are needed: the emulator encrypts
 * its 32-byte random to the SoC modulus (public) and shares an AES session
 * key with FS. No private key exists anywhere in this tree.
 */
#ifndef GC_CRYPTO_H
#define GC_CRYPTO_H

#include "gc.h"

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t buf[64];
    size_t buflen;
} gc_sha256_t;

void gc_sha256_init(gc_sha256_t *s);
void gc_sha256_update(gc_sha256_t *s, const void *data, size_t len);
void gc_sha256_final(gc_sha256_t *s, uint8_t out[32]);
void gc_sha256(const void *data, size_t len, uint8_t out[32]);

void gc_hmac_sha256(const uint8_t *key, size_t keylen,
                    const void *msg, size_t msglen, uint8_t out[32]);

typedef struct {
    uint8_t rk[176]; /* 11 round keys */
} gc_aes128_t;

void gc_aes128_init(gc_aes128_t *a, const uint8_t key[16]);
void gc_aes128_encrypt_block(const gc_aes128_t *a, const uint8_t in[16], uint8_t out[16]);
void gc_aes128_decrypt_block(const gc_aes128_t *a, const uint8_t in[16], uint8_t out[16]);

/* len must be a multiple of 16. in and out may alias. */
void gc_aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len);
void gc_aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len);

/* Counter is a 16-byte big-endian block, incremented per block (in place). */
void gc_aes128_ctr(const uint8_t key[16], uint8_t ctr[16],
                   const uint8_t *in, uint8_t *out, size_t len);

/* XTS-AES-128 over one data unit (IEEE 1619): key = data key || tweak key,
 * tweak = the 16-byte tweak block before encryption (the caller chooses its
 * byte order). len must be a multiple of 16; buf is processed in place. */
void gc_aes128_xts(const uint8_t key[32], const uint8_t tweak[16], uint8_t *buf,
                   size_t len, bool encrypt);

/* n: 256-byte big-endian modulus. seed: 32 bytes of entropy, explicit so the
 * transform is deterministic under test. Returns 0, or -1 if mlen > 190. */
int gc_rsa2048_oaep_sha256_encrypt(const uint8_t n[256], const uint8_t *msg,
                                   size_t mlen, const uint8_t seed[32],
                                   uint8_t out[256]);

/* Raw c = in^exp mod n, big-endian 256-byte operands. Used by the emulator
 * (exp = 65537) and by the host test driver (exp = d, test key only). */
int gc_rsa2048_raw(const uint8_t n[256], const uint8_t *exp, size_t explen,
                   const uint8_t in[256], uint8_t out[256]);

#endif /* GC_CRYPTO_H */
