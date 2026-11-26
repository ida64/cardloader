/* sim/fs.c - the "FS" side of the Lotus3 conversation.
 *
 * This is a faithful driver for the protocol in core/lotus3.c: same session
 * derivation, same CBC/CTR placement, same operation order. It owns the SoC
 * private key ONLY so it can decrypt the emulator's RSA-OAEP random; the
 * emulator never needs it.
 */
#include <stdio.h>
#include <stdlib.h>
#include "sim.h"
#include "crypto.h"
#include "gc_cert.h"

/* Test-only 2048-bit SoC keypair (generated for these vectors). Not a
 * secret and not used by the device build. */
static const char *SOC_N_HEX =
    "a1332a64d9fec6ce022d5a09bb74cb481c6145677ad66e44f92d904442f0438d"
    "c91344bef532a52332e32b30f6e451f555431b70d8e95eee1bba9ed1690b75bc"
    "9863b5de65ab2ed35d10ad05dc9b454ddcac6917a85de432268f8387cbbadd4b"
    "7fbe2de5a0b4ce41d061b0e8d12b33756b54595656c694d10ca141ae349a6e09"
    "d4905117a4a21cfe2f27b8c400862119674e524747a4c5dba69aae9317ee2ebc"
    "a1242e374840c29de1339cdba8b2c9c7cf756400d468d71761102cc9759bc737"
    "d29921d389b982c855d8b120942eac962d6330b2f914b9adaa58864b0f1e5033"
    "7cc6542f40c648ae59fea01f4e5163422430ece3d20120db39d75385750f300b";
static const char *SOC_D_HEX =
    "1f167e038b231e76166766a8dfd50b6b31c5f49b9b4e056019ea169b8389508d"
    "e48c69c2a609095dfb6f6222044b4e1f113d6aea5d7acc4b01600147038a293f"
    "a0e801e80d15716763d85675fdf097f2072fdce8aa18c96c7e9148dd8485da2d"
    "b84a1611e5e758abcaa33c79f9f4e9eca83151355c70d9bc63422a278d8f86ce"
    "e1dfff553696cf7709df1ed52ea584f3d52483b0e2673e81102e0c2278bf1a3d"
    "0c10a86beb4bf49e126ac003ec339444c2880d549d0085483203efdc6305e6fa"
    "b530094052b9d0287d8a69f8a4b3ffd4807d60be7540d137e390ade77a558b83"
    "8f8694424087ffabf17736aed5d918ada95e68ad47d08c9f95df4d64a3824e81";

enum { M_PLAIN = 0, M_CBC = 1, M_CTR = 2 };

typedef struct {
    l3_t *l3;
    uint8_t key[16], iv[16];
    bool secure, key_ready;
    uint8_t cv[16];
    uint8_t soc_n[256], soc_d[256];
    int fails;
} fs_t;

static void unhex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void mgf1(const uint8_t *seed, size_t slen, uint8_t *out, size_t olen)
{
    uint8_t buf[260], h[32];
    memcpy(buf, seed, slen);
    size_t done = 0;
    for (uint32_t c = 0; done < olen; c++) {
        buf[slen] = (uint8_t)(c >> 24);
        buf[slen + 1] = (uint8_t)(c >> 16);
        buf[slen + 2] = (uint8_t)(c >> 8);
        buf[slen + 3] = (uint8_t)c;
        gc_sha256(buf, slen + 4, h);
        size_t n = olen - done < 32 ? olen - done : 32;
        memcpy(out + done, h, n);
        done += n;
    }
}

/* OAEP-SHA256 decode after the raw RSA private op. Returns message length. */
static int oaep_decode(const uint8_t *em, uint8_t *msg, size_t max)
{
    uint8_t lhash[32], seed[32], db[223], tmp[223];
    gc_sha256("", 0, lhash);
    if (em[0] != 0)
        return -1;
    const uint8_t *masked_seed = em + 1;
    const uint8_t *masked_db = em + 33;
    mgf1(masked_db, 223, tmp, 32);
    for (int i = 0; i < 32; i++)
        seed[i] = masked_seed[i] ^ tmp[i];
    mgf1(seed, 32, tmp, 223);
    for (int i = 0; i < 223; i++)
        db[i] = masked_db[i] ^ tmp[i];
    if (memcmp(db, lhash, 32) != 0)
        return -1;
    size_t i = 32;
    while (i < 223 && db[i] == 0)
        i++;
    if (i >= 223 || db[i] != 0x01)
        return -1;
    i++;
    size_t n = 223 - i;
    if (n > max)
        return -1;
    memcpy(msg, db + i, n);
    return (int)n;
}

static int mode_for(const fs_t *f, uint8_t op)
{
    if (f->secure)
        return M_CTR;
    if (op >= 0x06 && op <= 0x09)
        return M_CBC;
    return M_PLAIN;
}

static int xfer(fs_t *f, uint8_t op, const uint8_t od[0x1F],
                void *rbuf, size_t rlen, const void *wbuf, size_t wlen)
{
    uint8_t hdr[GC_OP_SIZE];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = op;
    if (od)
        memcpy(hdr + 1, od, 0x1F);

    int mode = mode_for(f, op);
    uint8_t cv[16];
    memcpy(cv, f->cv, 16);
    if (mode == M_CTR)
        memcpy(hdr + 0x20, f->cv, 16);
    for (int i = 15; i >= 0; i--)
        if (++f->cv[i])
            break;

    if (l3_cmd60(f->l3, hdr)) {
        printf("  ! CMD60 op 0x%02x rejected\n", op);
        f->fails++;
        return -1;
    }

    if (wlen) {
        uint8_t *tmp = (uint8_t *)malloc(wlen);
        memcpy(tmp, wbuf, wlen);
        if (mode == M_CBC)
            gc_aes128_cbc_encrypt(f->key, f->iv, tmp, tmp, wlen);
        else if (mode == M_CTR)
            gc_aes128_ctr(f->key, cv, tmp, tmp, wlen);
        int rc = l3_data_write(f->l3, tmp, wlen);
        free(tmp);
        if (rc) {
            printf("  ! write phase op 0x%02x failed\n", op);
            f->fails++;
            return -1;
        }
    }
    if (rlen) {
        if (l3_data_read(f->l3, rbuf, rlen)) {
            printf("  ! read phase op 0x%02x failed\n", op);
            f->fails++;
            return -1;
        }
        if (mode == M_CBC)
            gc_aes128_cbc_decrypt(f->key, f->iv, rbuf, rbuf, rlen);
        else if (mode == M_CTR)
            gc_aes128_ctr(f->key, cv, rbuf, rbuf, rlen);
    }

    uint32_t st;
    if (l3_cmd61(f->l3, &st) || st) {
        printf("  ! CMD61 op 0x%02x status=%u\n", op, st);
        f->fails++;
        return -1;
    }
    return 0;
}

static void derive(fs_t *f, const uint8_t *asic_rand)
{
    uint8_t msg[64], mac[32], type = 0x0F;
    memcpy(msg, asic_rand, 32);
    memset(msg + 32, 0x11, 32); /* FS's RNG hook */
    gc_hmac_sha256(&type, 1, msg, sizeof(msg), mac);
    memcpy(f->key, mac, 16);
    memcpy(f->iv, mac + 16, 16);
    f->key_ready = true;
}

#define CHECK(cond, ...) do { \
    if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); f.fails++; } \
} while (0)

int fs_handshake(l3_t *l3, gc_xci_t *xci, bool verbose)
{
    fs_t f;
    memset(&f, 0, sizeof(f));
    f.l3 = l3;
    unhex(SOC_N_HEX, f.soc_n, 256);
    unhex(SOC_D_HEX, f.soc_d, 256);

    // 0x01 SendFirmware: 0x7800-byte LAFW, type byte at 0x110.
    uint8_t *lafw = (uint8_t *)calloc(1, 0x7800);
    memcpy(lafw + 0x100, "LAFW", 4);
    lafw[0x110] = 0x0F;
    CHECK(xfer(&f, 0x01, NULL, NULL, 0, lafw, 0x7800) == 0, "SendFirmware");
    free(lafw);
    if (verbose) printf("  SendFirmware (type 0x0F)\n");

    // 0x02 ReceiveCertificate.
    uint8_t cert[0x400];
    CHECK(xfer(&f, 0x02, NULL, cert, sizeof(cert), NULL, 0) == 0, "ReceiveCertificate");
    /* FS parses the block from offset 0 and verifies the signature with its
     * baked-in CA key. Same key, same PKCS#1 v1.5 check, run here. */
    CHECK(gc_cert_verify_fs(cert, sizeof(cert)) == 0,
          "certificate signature rejected by FS's CA key");
    if (verbose) printf("  ReceiveCertificate: 0x400 bytes, FS CA check PASS\n");

    // 0x03 SendSocCertificate: modulus at +0x130.
    uint8_t soc[0x400];
    memset(soc, 0, sizeof(soc));
    memcpy(soc, "CERT", 4);
    memcpy(soc + 0x130, f.soc_n, 256);
    soc[0x230] = 0x01; soc[0x231] = 0x00; soc[0x232] = 0x01;
    CHECK(xfer(&f, 0x03, NULL, NULL, 0, soc, sizeof(soc)) == 0, "SendSocCertificate");

    // 0x04 ReceiveRandomValue: decrypt with the SoC key.
    uint8_t ct[0x100], em[256], asic_rand[32];
    CHECK(xfer(&f, 0x04, NULL, ct, sizeof(ct), NULL, 0) == 0, "ReceiveRandomValue");
    CHECK(gc_rsa2048_raw(f.soc_n, f.soc_d, 256, ct, em) == 0, "RSA private op");
    int mlen = oaep_decode(em, asic_rand, sizeof(asic_rand));
    CHECK(mlen == 32, "OAEP decode produced %d bytes", mlen);
    CHECK(memcmp(asic_rand, l3->asic_rand, 32) == 0, "ASIC random mismatch");
    if (verbose) printf("  ReceiveRandomValue: RSA-OAEP decoded, matches emulator\n");

    // 0x05 SendRandomValue: ignored by the emulator.
    uint8_t junk[0x100];
    memset(junk, 0x5A, sizeof(junk));
    CHECK(xfer(&f, 0x05, NULL, NULL, 0, junk, sizeof(junk)) == 0, "SendRandomValue");

    derive(&f, asic_rand);
    if (verbose) printf("  session key derived from both randoms\n");

    // 0x06/0x07 device challenge.
    uint8_t dc[0x200];
    CHECK(xfer(&f, 0x06, NULL, dc, sizeof(dc), NULL, 0) == 0, "ReceiveDeviceChallenge");
    uint8_t dcr[0x200];
    memset(dcr, 0x77, sizeof(dcr));
    CHECK(xfer(&f, 0x07, NULL, NULL, 0, dcr, sizeof(dcr)) == 0, "RespondDeviceChallenge");

    // 0x08/0x09 host challenge round trip.
    uint8_t host_ch[32];
    for (int i = 0; i < 32; i++)
        host_ch[i] = (uint8_t)(0xA0 + i);
    uint8_t hpage[0x200];
    memset(hpage, 0, sizeof(hpage));
    memcpy(hpage, host_ch, 32);
    CHECK(xfer(&f, 0x08, NULL, NULL, 0, hpage, sizeof(hpage)) == 0, "SendHostChallenge");

    uint8_t resp[0x200];
    CHECK(xfer(&f, 0x09, NULL, resp, sizeof(resp), NULL, 0) == 0, "ReceiveChallengeResponse");
    CHECK(memcmp(resp, host_ch, 32) == 0, "challenge response mismatch: session keys differ");
    if (verbose) printf("  host challenge echoed back: session established\n");

    // 0x0A ChangeModeToSecure.
    CHECK(xfer(&f, 0x0A, NULL, NULL, 0, NULL, 0) == 0, "ChangeModeToSecure");
    f.secure = true;

    // 0x0F ChangeGcModeToSecure: CardKeyArea.
    uint8_t ka[0x800];
    CHECK(xfer(&f, 0x0F, NULL, ka, sizeof(ka), NULL, 0) == 0, "ChangeGcModeToSecure");
    CHECK(memcmp(ka + 0x600, l3->initial_data, 0x200) == 0, "InitialData mismatch");
    uint8_t idhash[32];
    gc_sha256(ka + 0x600, 0x200, idhash);
    bool sig_ok = memcmp(idhash, l3->card_header + 0x68, 32) == 0;
    if (verbose) {
        printf("  CardKeyArea: cert %s, InitialData hash %s\n",
               "served", sig_ok ? "matches header" : "does NOT match header (needs FS patch)");
    }
    if (!l3->skip_initdata_check)
        CHECK(sig_ok, "InitialData hash does not match signed header");

    // 0x0E GetCardHeader: signed bytes must be verbatim.
    uint8_t hdr[0x200];
    CHECK(xfer(&f, 0x0E, NULL, hdr, sizeof(hdr), NULL, 0) == 0, "GetCardHeader");
    CHECK(memcmp(hdr + 8, xci->header + 0x100, 0x100) == 0, "served header changed signed bytes");
    CHECK(memcmp(hdr + 8, "HEAD", 4) == 0, "served header magic");
    if (verbose) printf("  GetCardHeader: HEAD, 0x100 signed bytes byte-identical\n");

    // 0x10 SendCardCommand ReadPage (FS 23.5 multi-page wrapper).
    struct { uint32_t page; const char *what; } probes[] = {
        {0x00, "CardHeader"},
        {0x78, "HFS0 root (image 0x10000)"},
        {0x7A, "root file data (image 0x10400)"},
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        uint8_t od[0x1F] = {0};
        od[0] = 3;       /* multi-page wrapper */
        od[1] = 0;       /* read */
        gc_wr32(od + 3, 1);             /* count, little-endian */
        od[7] = 0x5B;    /* ReadPage */
        gc_wr32be(od + 8, probes[i].page); /* page, big-endian */
        uint8_t page[0x200], want[0x200];
        if (xfer(&f, 0x10, od, page, sizeof(page), NULL, 0))
            continue;
        CHECK(gc_image_read(xci->img, (uint64_t)l3->page_base +
                             (uint64_t)probes[i].page * 0x200, want, 0x200) == 0,
              "source read page 0x%x", probes[i].page);
        CHECK(memcmp(page, want, 0x200) == 0, "page 0x%x mismatch (%s)", probes[i].page, probes[i].what);
        if (verbose) printf("  ReadPage 0x%03x: %s ok\n", probes[i].page, probes[i].what);
    }
    if (verbose) printf("  pages served: %llu\n", (unsigned long long)l3->pages_served);

    return f.fails ? -1 : 0;
}

/* Raw path: the same activation through the FS 22.5.0 executor boundary.
 * No CBC/CTR, no RSA session handshake; op 0x04 still needs a real RSA-OAEP
 * to the SoC modulus because FS decrypts it above this boundary. */
int fs_handshake_raw(gc_asic_t *a, gc_xci_t *xci, bool verbose)
{
    int fails = 0;
    uint8_t soc_n[256], soc_d[256];
    unhex(SOC_N_HEX, soc_n, 256);
    unhex(SOC_D_HEX, soc_d, 256);

    uint8_t hdr[GC_OP_SIZE];
    uint32_t st = 0;

#define RX(opv, od, data, len) do {                                            \
        memset(hdr, 0, sizeof(hdr));                                           \
        hdr[0] = (uint8_t)(opv);                                               \
        if (od) memcpy(hdr + 1, (od), 0x1F);                                   \
        if (gc_asic_exec(a, &st, (data), (len), hdr) || st) {                  \
            printf("FAIL: executor op 0x%02x status=%u\n", (opv), st);        \
            fails++;                                                           \
        }                                                                      \
    } while (0)
#define RCHECK(cond, ...) do {                                                 \
        if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; }  \
    } while (0)

    uint8_t *lafw = (uint8_t *)calloc(1, 0x7800);
    memcpy(lafw + 0x100, "LAFW", 4);
    lafw[0x110] = 0x0F;
    RX(0x01, NULL, lafw, 0x7800);
    free(lafw);
    if (verbose) printf("  op 0x01 SendFirmware (plaintext)\n");

    uint8_t cert[0x400];
    RX(0x02, NULL, cert, sizeof(cert));
    if (gc_cert_verify_fs(cert, sizeof(cert)) != 0)
        printf("FAIL certificate does not verify against FS's CA key\n");
    else if (verbose)
        printf("  op 0x02 ReceiveCertificate: FS CA check PASS\n");

    uint8_t soc[0x400];
    memset(soc, 0, sizeof(soc));
    memcpy(soc + 0x130, soc_n, 256);
    soc[0x230] = 0x01; soc[0x231] = 0x00; soc[0x232] = 0x01;
    RX(0x03, NULL, soc, sizeof(soc));

    uint8_t ct[0x100], em[256], asic_rand[32];
    RX(0x04, NULL, ct, sizeof(ct));
    if (gc_rsa2048_raw(soc_n, soc_d, 256, ct, em)) {
        printf("FAIL: RSA private op\n");
        fails++;
    }
    int mlen = oaep_decode(em, asic_rand, sizeof(asic_rand));
    RCHECK(mlen == 32, "OAEP decode produced %d bytes", mlen);
    RCHECK(memcmp(asic_rand, a->l3.asic_rand, 32) == 0, "ASIC random mismatch");
    if (verbose) printf("  op 0x04 ASIC random decrypts to the emulator's value\n");

    uint8_t junk[0x100];
    memset(junk, 0x5A, sizeof(junk));
    RX(0x05, NULL, junk, sizeof(junk));

    uint8_t dc[0x200], dcr[0x200];
    RX(0x06, NULL, dc, sizeof(dc));
    memset(dcr, 0x77, sizeof(dcr));
    RX(0x07, NULL, dcr, sizeof(dcr));

    uint8_t host_ch[32], hpage[0x200], resp[0x200];
    for (int i = 0; i < 32; i++) host_ch[i] = (uint8_t)(0xA0 + i);
    memset(hpage, 0, sizeof(hpage));
    memcpy(hpage, host_ch, 32);
    RX(0x08, NULL, hpage, sizeof(hpage));
    RX(0x09, NULL, resp, sizeof(resp));
    RCHECK(memcmp(resp, host_ch, 32) == 0, "challenge echo mismatch");
    if (verbose) printf("  op 0x08/0x09 challenge echoes in plaintext\n");

    RX(0x0A, NULL, NULL, 0); /* ChangeModeToSecure: accepted, no data */

    uint8_t ka[0x800];
    RX(0x0F, NULL, ka, sizeof(ka));
    RCHECK(memcmp(ka + 0x600, a->l3.initial_data, 0x200) == 0, "InitialData mismatch");
    if (verbose) printf("  op 0x0F CardKeyArea served, InitialData present\n");

    uint8_t h[0x200];
    RX(0x0E, NULL, h, sizeof(h));
    RCHECK(memcmp(h + 8, xci->header + 0x100, 0x100) == 0, "signed header changed");
    if (verbose) printf("  op 0x0E GetCardHeader: signed bytes verbatim\n");

    struct { uint32_t page; const char *what; } probes[] = {
        {0x80, "HFS0 root"},
        {0x08, "CardHeader"},
        {0x82, "partition data"},
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        uint8_t od[0x1F];
        memset(od, 0, sizeof(od));
        od[0] = 1;
        od[1] = 0;
        gc_wr32(od + 3, probes[i].page);
        od[7] = 0x5B;
        uint8_t page[0x200], want[0x200];
        RX(0x10, od, page, sizeof(page));
        RCHECK(gc_image_read(xci->img, (uint64_t)probes[i].page * 0x200, want, 0x200) == 0,
               "source read page 0x%x", probes[i].page);
        RCHECK(memcmp(page, want, 0x200) == 0, "page 0x%x mismatch", probes[i].page);
        if (verbose) printf("  op 0x10 ReadPage 0x%03x: %s ok\n", probes[i].page, probes[i].what);
    }

#undef RX
#undef RCHECK
    return fails ? -1 : 0;
}
