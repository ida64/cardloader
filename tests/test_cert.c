/* Certificate path tests: FS 23.5.0's CA key accepting the genuine CN=LOTUS3
 * certificate, and rejecting tampered variants.
 *
 * This is the check SX OS relied on when it served a real certificate instead
 * of hooking FS's PKCS#1 v1.5 verifier. */
#include <stdio.h>
#include <string.h>
#include "gc_cert.h"

static int fails;

static int contains(const uint8_t *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0)
            return 1;
    }
    return 0;
}

static void ok(const char *name, int cond)
{
    if (cond) {
        printf("ok   %s\n", name);
    } else {
        printf("FAIL %s\n", name);
        fails++;
    }
}

int main(void)
{
    size_t der_len = 0;
    const uint8_t *der = gc_cert_der(&der_len);

    /* 782-byte DER, subject CN=LOTUS3, issuer CN=LOTUS_CA1. */
    ok("cert length", der_len == 782);
    ok("cert parses as SEQUENCE", der[0] == 0x30 && der[1] == 0x82);
    ok("subject CN=LOTUS3 present", contains(der, der_len, "LOTUS3"));
    ok("issuer CN=LOTUS_CA1 present", contains(der, der_len, "LOTUS_CA1"));

    /* The documented result: FS's baked-in CA key accepts the certificate. */
    ok("FS CA check accepts genuine cert", gc_cert_verify_fs(der, der_len) == 0);

    /* The block the ASIC actually serves (DER + zero padding). */
    uint8_t block[GC_CERT_BLOCK_SIZE];
    gc_cert_block(block);
    ok("served block is zero padded",
       block[der_len] == 0 && block[GC_CERT_BLOCK_SIZE - 1] == 0);
    ok("FS CA check accepts served block",
       gc_cert_verify_fs(block, sizeof(block)) == 0);

    /* Tampering must fail: one bit in the TBS, one in the signature. */
    uint8_t bad[GC_CERT_BLOCK_SIZE];
    memcpy(bad, block, sizeof(bad));
    bad[64] ^= 0x01;
    ok("tampered TBS rejected", gc_cert_verify_fs(bad, sizeof(bad)) != 0);

    memcpy(bad, block, sizeof(bad));
    bad[780] ^= 0x01;
    ok("tampered signature rejected", gc_cert_verify_fs(bad, sizeof(bad)) != 0);

    /* A block that is not a certificate at all must be rejected, not crash. */
    memset(bad, 0, sizeof(bad));
    ok("empty block rejected", gc_cert_verify_fs(bad, sizeof(bad)) != 0);
    ok("truncated block rejected", gc_cert_verify_fs(block, 16) != 0);

    if (fails) {
        printf("FAIL: %d\n", fails);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
