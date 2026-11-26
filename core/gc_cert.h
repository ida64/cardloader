/* gc_cert.h - the gamecard certificate path.
 *
 * SX OS did not hook FS's certificate check. It served a genuine CN=LOTUS3
 * certificate and let FS's untouched PKCS#1 v1.5 verifier accept it. This
 * module carries both halves of that check so the acceptance can be
 * reproduced on the host:
 *
 *   - the 782-byte DER certificate FS receives in op 0x02, padded to the
 *     0x400-byte block the ASIC returns;
 *   - FS 23.5.0's own CA public key (modulus at 0x1F1DE8, e = 0x010001) and
 *     the PKCS#1 v1.5 SHA-256 comparison FS performs on it.
 *
 * The key material is public: the certificate is served by the ASIC, the
 * modulus is FS's baked-in CA key.
 */
#ifndef GC_CERT_H
#define GC_CERT_H

#include "gc.h"

/* Size of the op 0x02 payload. */
#define GC_CERT_BLOCK_SIZE 0x400

/* The DER certificate (782 bytes): subject CN=LOTUS3, issuer CN=LOTUS_CA1. */
const uint8_t *gc_cert_der(size_t *len);

/* The certificate as the ASIC serves it: DER at offset 0, zero padded. */
void gc_cert_block(uint8_t out[GC_CERT_BLOCK_SIZE]);

/* Reproduces FS 23.5.0's check with FS's own key: RSA public operation over
 * the certificate signature, then the PKCS#1 v1.5 SHA-256 DigestInfo
 * comparison. Returns 0 when FS accepts the certificate, -1 otherwise. */
int gc_cert_verify_fs(const uint8_t *der, size_t len);

#endif /* GC_CERT_H */
