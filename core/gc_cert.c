/* gc_cert.c - serve and verify the gamecard certificate the way FS does.
 *
 * No private key and no signature bypass is involved: FS accepts op 0x02's
 * certificate because the certificate is genuine and FS's PKCS#1 v1.5
 * verifier is left untouched. gc_cert_verify_fs() performs the same operation
 * with FS 23.5.0's own CA modulus, so the demo can prove acceptance instead of
 * asserting it.
 */
#include "gc_cert.h"
#include "crypto.h"

#include "gc_cert_data.h"

#define DER_SEQ 0x30
#define DER_BITSTRING 0x03

const uint8_t *gc_cert_der(size_t *len)
{
    if (len)
        *len = sizeof(gc_cert_der_bytes);
    return gc_cert_der_bytes;
}

void gc_cert_block(uint8_t out[GC_CERT_BLOCK_SIZE])
{
    memset(out, 0, GC_CERT_BLOCK_SIZE);
    memcpy(out, gc_cert_der_bytes, sizeof(gc_cert_der_bytes));
}

/* Read one DER TLV at off. On success *tag is the identifier, *body the offset
 * of the contents and *blen the content length. Returns the offset just past
 * the TLV, or (size_t)-1. */
static size_t der_tlv(const uint8_t *b, size_t len, size_t off,
                      uint8_t *tag, size_t *body, size_t *blen)
{
    if (off + 2 > len)
        return (size_t)-1;
    *tag = b[off++];
    size_t l = b[off++];
    if (l & 0x80) {
        size_t n = l & 0x7F;
        if (n == 0 || n > 3 || off + n > len)
            return (size_t)-1;
        l = 0;
        for (size_t i = 0; i < n; i++)
            l = (l << 8) | b[off++];
    }
    if (off + l > len)
        return (size_t)-1;
    *body = off;
    *blen = l;
    return off + l;
}

/* PKCS#1 v1.5: EM = 0x00 || 0x01 || PS(0xFF..) || 0x00 || DigestInfo || H */
static int pkcs1_v15_sha256_check(const uint8_t em[256], const uint8_t hash[32])
{
    static const uint8_t digest_info_prefix[] = {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    const size_t prefix_len = sizeof(digest_info_prefix);

    if (em[0] != 0x00 || em[1] != 0x01)
        return -1;

    size_t i = 2;
    while (i < 256 && em[i] == 0xFF)
        i++;
    if (i == 2 || i >= 256 || em[i] != 0x00)
        return -1;
    i++;

    /* DigestInfo is the trailing 19 + 32 bytes. */
    if (256 - i != prefix_len + 32)
        return -1;
    if (memcmp(em + i, digest_info_prefix, prefix_len) != 0)
        return -1;
    if (memcmp(em + i + prefix_len, hash, 32) != 0)
        return -1;
    return 0;
}

int gc_cert_verify_fs(const uint8_t *der, size_t len)
{
    if (!der || len < 4)
        return -1;

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
     *                            signatureValue BIT STRING } */
    uint8_t tag;
    size_t body, blen;
    size_t next = der_tlv(der, len, 0, &tag, &body, &blen);
    if (next == (size_t)-1 || tag != DER_SEQ)
        return -1;

    const size_t tbs_start = body;
    size_t tbs_hdr, tbs_len;
    size_t p = der_tlv(der, len, tbs_start, &tag, &tbs_hdr, &tbs_len);
    if (p == (size_t)-1 || tag != DER_SEQ)
        return -1;

    /* signatureAlgorithm */
    p = der_tlv(der, len, p, &tag, &body, &blen);
    if (p == (size_t)-1 || tag != DER_SEQ)
        return -1;

    /* signatureValue */
    p = der_tlv(der, len, p, &tag, &body, &blen);
    if (p == (size_t)-1 || tag != DER_BITSTRING || blen != 257 || der[body] != 0)
        return -1;
    const uint8_t *sig = der + body + 1;

    const size_t tbs_total = tbs_hdr + tbs_len - tbs_start;

    uint8_t em[256];
    if (gc_rsa2048_raw(gc_fs_ca_modulus, gc_fs_ca_exponent,
                       sizeof(gc_fs_ca_exponent), sig, em) != 0)
        return -1;

    uint8_t hash[32];
    gc_sha256(der + tbs_start, tbs_total, hash);

    return pkcs1_v15_sha256_check(em, hash);
}
