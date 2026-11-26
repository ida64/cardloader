/* Known-answer tests for the core crypto. Vectors generated independently
 * (hashlib/hmac/cryptography in Python) and from FIPS-197. */
#include <stdio.h>
#include <string.h>
#include "crypto.h"

static int fails;

static int unhex(const char *s, uint8_t *out, size_t max)
{
    size_t n = strlen(s) / 2;
    if (n > max)
        return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return (int)n;
}

static void chk(const char *name, const uint8_t *got, const uint8_t *want, size_t n)
{
    if (memcmp(got, want, n)) {
        printf("FAIL %s\n  got  ", name);
        for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n  want ");
        for (size_t i = 0; i < n; i++) printf("%02x", want[i]);
        printf("\n");
        fails++;
    } else {
        printf("ok   %s\n", name);
    }
}

static void test_sha_hmac(void)
{
    uint8_t got[32], want[32];
    gc_sha256("abc", 3, got);
    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
    chk("sha256(abc)", got, want, 32);

    /* streaming split must equal one-shot */
    gc_sha256_t s;
    gc_sha256_init(&s);
    gc_sha256_update(&s, "a", 1);
    gc_sha256_update(&s, "bc", 2);
    gc_sha256_final(&s, got);
    chk("sha256(abc) streamed", got, want, 32);

    uint8_t key[16], msg[5] = {'h', 'e', 'l', 'l', 'o'};
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    gc_hmac_sha256(key, 16, msg, 5, got);
    unhex("9163eb0d568a28e3994c969c9d5dfef181ccbbb0a8742b30464d4d200cbcb4f4", want, 32);
    chk("hmac-sha256", got, want, 32);
}

static void test_aes(void)
{
    uint8_t key[16], pt[16], ct[16], back[16], want[16];
    unhex("000102030405060708090a0b0c0d0e0f", key, 16);
    unhex("00112233445566778899aabbccddeeff", pt, 16);
    unhex("69c4e0d86a7b0430d8cdb78070b4c55a", want, 16);

    gc_aes128_t a;
    gc_aes128_init(&a, key);
    gc_aes128_encrypt_block(&a, pt, ct);
    chk("aes128 fips197 enc", ct, want, 16);
    gc_aes128_decrypt_block(&a, ct, back);
    chk("aes128 fips197 dec", back, pt, 16);

    /* CBC/CTR round trips */
    uint8_t iv[16], buf[64], enc[64], dec[64];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(i * 7);
    gc_aes128_cbc_encrypt(key, iv, buf, enc, 64);
    gc_aes128_cbc_decrypt(key, iv, enc, dec, 64);
    chk("aes128 cbc roundtrip", dec, buf, 64);

    uint8_t ctr[16], ctr2[16];
    memcpy(ctr, iv, 16); memcpy(ctr2, iv, 16);
    gc_aes128_ctr(key, ctr, buf, enc, 64);
    gc_aes128_ctr(key, ctr2, enc, dec, 64);
    chk("aes128 ctr roundtrip", dec, buf, 64);
}

static void test_rsa_oaep(void)
{
    uint8_t n[256], seed[32], msg[32], got[256], want[256];
    const char *nh =
        "a1332a64d9fec6ce022d5a09bb74cb481c6145677ad66e44f92d904442f0438d"
        "c91344bef532a52332e32b30f6e451f555431b70d8e95eee1bba9ed1690b75bc"
        "9863b5de65ab2ed35d10ad05dc9b454ddcac6917a85de432268f8387cbbadd4b"
        "7fbe2de5a0b4ce41d061b0e8d12b33756b54595656c694d10ca141ae349a6e09"
        "d4905117a4a21cfe2f27b8c400862119674e524747a4c5dba69aae9317ee2ebc"
        "a1242e374840c29de1339cdba8b2c9c7cf756400d468d71761102cc9759bc737"
        "d29921d389b982c855d8b120942eac962d6330b2f914b9adaa58864b0f1e5033"
        "7cc6542f40c648ae59fea01f4e5163422430ece3d20120db39d75385750f300b";
    const char *cth =
        "3162ab5badaddfe03d1233266626b469f86e6a8706afc64cb2b3d30e01180b7d"
        "e246c9c39967d9ebc381afdd7fbded92f3ec1fbdef97c2dc0dcf2d8a16c97c86"
        "e134c536168d6a518ce0af174022726aafb8bd701568f35a912179993aa0b5b5"
        "8fce55481527450592506a8e16c1d3e8067497a9fcb0df2cc2e7ac65cc025ccb"
        "a1bf797432c35fd800e31b2631dc7ee1570e5e0f6b9bdbea47724e0d59bdbf2e"
        "ded391e06a3af20a5eb329de36f150b7bb2b321fadfacc121287307f6b0e1e14"
        "490335e5280544699cef93f7cb371c14c62c4190311bc76433687b14ba4db0b9"
        "665b4ad80df2c77d1f96b7d64568df5884a29972c4df0f358bd9a4ffb5e1ff31";
    unhex(nh, n, 256);
    unhex(cth, want, 256);
    memset(seed, 0xa5, 32);
    for (int i = 0; i < 32; i++) msg[i] = (uint8_t)i;

    int rc = gc_rsa2048_oaep_sha256_encrypt(n, msg, 32, seed, got);
    if (rc) { printf("FAIL rsa oaep rc=%d\n", rc); fails++; return; }
    chk("rsa2048 oaep-sha256", got, want, 256);
}

int main(void)
{
    test_sha_hmac();
    test_aes();
    test_rsa_oaep();
    if (fails) { printf("\n%d FAILURE(S)\n", fails); return 1; }
    printf("\nall crypto vectors pass\n");
    return 0;
}
