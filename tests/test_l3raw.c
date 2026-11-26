/* Regression: FS 23.5.0's challenge exchange (sub_1899B0) through the same
 * path the hook takes.
 *
 * Ops 6-9 carry 32-byte logical transfers in 0x200-byte DMA frames. Writes
 * reach the executor detour in plaintext (FS encrypts inside the executor,
 * which the detour replaces). Reads are decrypted by FS after the executor
 * returns (sub_18B790): AES-128-CBC with the session key/IV once the session
 * is keyed, AES-128-CTR with the live counter in secure mode. So op 9 must
 * answer SHA-256(op 8 bytes) AND the frame must be sealed with FS's session
 * state, or FS's memcmp fails with 2002-2655. */
#include <stdio.h>
#include <string.h>
#include "asic.h"
#include "crypto.h"

#define FRAME 0x200

static int fails;
static uint8_t rng_counter;

static void rng(void *ctx, void *out, size_t len)
{
    uint8_t *p = out;
    (void)ctx;
    for (size_t i = 0; i < len; i++)
        p[i] = ++rng_counter;
}

static void chk(const char *name, int cond)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        fails++;
}

static void hdr_for(uint8_t hdr[GC_OP_SIZE], uint8_t op)
{
    memset(hdr, 0, GC_OP_SIZE);
    hdr[0] = op;
}

/* FS's session as sub_18B790 sees it. */
typedef struct {
    gc_link_t mode;
    uint8_t key[16];
    uint8_t iv[16];  /* CBC: fixed session IV */
    uint8_t ctr[16]; /* CTR: live counter, advanced by every decrypt */
} fs_session_t;

/* One decrypt call of sub_18B790 (sub_190560 / sub_190600). */
static void fs_decrypt(fs_session_t *s, uint8_t *dst, const uint8_t *src, size_t n)
{
    if (s->mode == GC_LINK_CTR)
        gc_aes128_ctr(s->key, s->ctr, src, dst, n); /* advances ctr by n/16 */
    else
        gc_aes128_cbc_decrypt(s->key, s->iv, src, dst, n);
}

/* sub_18B790(dst, a3, dma, a5): FS's copy-out after a device -> host op. */
static void fs_copy_out(fs_session_t *s, uint8_t *dst, size_t a3, uint8_t *dma, size_t a5)
{
    size_t v11 = a3 < a5 ? a3 : a5;
    if (s->mode == GC_LINK_PLAIN) {
        memcpy(dst, dma, v11);
        return;
    }
    size_t v12 = a3 & ~(size_t)15;
    size_t v13 = v11 == v12 ? v12 : v12 + 16;
    fs_decrypt(s, dst, dma, v12);
    if (a5 >= v13 && v12 < v13) {
        uint8_t blk[16];
        fs_decrypt(s, blk, dma + v12, 16);
        memcpy(dst + v12, blk, v11 - v12);
    }
    if (a5 > v13)
        fs_decrypt(s, dma + v13, dma + v13, a5 - v13);
}

/* FS-held reply secrets, as hh_glue.c's finish_read hands them over; NULL
 * before the card is activated. */
static const gc_card_secrets_t *g_secrets;

/* A device -> host wrapper (sub_18A3C0 / sub_18A620 / ...): the detour serves
 * the DMA frame, completes and seals it like hh_glue.c's finish_read, FS
 * copies it out. */
static int fs_read_hdr(gc_asic_t *a, fs_session_t *s, const uint8_t hdr[GC_OP_SIZE],
                       uint8_t *dst, size_t a3, int seal)
{
    static uint8_t dma[0x10000];
    uint32_t st = 0xFFFF;
    size_t a5 = (a3 + 0x1FF) & ~(size_t)0x1FF;
    memset(dma, 0, sizeof(dma));
    int rc = gc_asic_exec(a, &st, dma, a5, hdr);
    if (g_secrets)
        gc_asic_authenticate(a, dma, a5, g_secrets);
    if (seal)
        gc_link_seal(s->mode, s->key, s->mode == GC_LINK_CTR ? s->ctr : s->iv,
                     dma, a5, a->l3.pending_len);
    fs_copy_out(s, dst, a3, dma, a5);
    return rc == 0 && st == 0 ? 0 : -1;
}

static int fs_read(gc_asic_t *a, fs_session_t *s, uint8_t op, uint8_t *dst, size_t a3, int seal)
{
    uint8_t hdr[GC_OP_SIZE];
    hdr_for(hdr, op);
    return fs_read_hdr(a, s, hdr, dst, a3, seal);
}

/* A host -> device wrapper (sub_18A4C0 / sub_18A570): mode 1, the detour
 * forwards FS's own buffer and length. */
static int fs_write(gc_asic_t *a, uint8_t op, const uint8_t *src, size_t len)
{
    uint8_t hdr[GC_OP_SIZE], buf[64];
    uint32_t st = 0xFFFF;
    hdr_for(hdr, op);
    memcpy(buf, src, len);
    int rc = gc_asic_exec(a, &st, buf, len, hdr);
    return rc == 0 && st == 0 ? 0 : -1;
}

/* sub_1899B0, returning 0 or 2655 at the final memcmp. */
static int fs_challenge(gc_asic_t *a, fs_session_t *s, int seal, uint8_t dev_out[32])
{
    uint8_t buf[32], hash[32], resp[32];
    if (fs_read(a, s, 0x06, buf, 32, seal))
        return 2651;
    memcpy(dev_out, buf, 32);
    gc_sha256(buf, 32, hash);
    if (fs_write(a, 0x07, hash, 32))
        return 2652;
    for (size_t i = 0; i < 32; i++) /* sub_190480: fresh host challenge */
        buf[i] = (uint8_t)(0xA0 + i);
    if (fs_write(a, 0x08, buf, 32))
        return 2654;
    gc_sha256(buf, 32, hash);
    memset(resp, 0, sizeof(resp));
    if (fs_read(a, s, 0x09, resp, 32, seal))
        return 2657;
    return memcmp(hash, resp, 32) ? 2655 : 0;
}

static void session(fs_session_t *s, gc_link_t mode)
{
    s->mode = mode;
    for (int i = 0; i < 16; i++) {
        s->key[i] = (uint8_t)(0x5A ^ i * 7);
        s->iv[i] = (uint8_t)(0xC3 + i);
        s->ctr[i] = (uint8_t)(i == 15 ? 0xFE : 0x10 + i); /* carry soon */
    }
}

#define IMG_SIZE 0x8000
static uint8_t g_img_buf[IMG_SIZE];
static const uint8_t k_header_key[16] = {
    0x61, 0x2F, 0x09, 0xB4, 0x7E, 0x33, 0xC0, 0x18, 0x55, 0xA2, 0x6D, 0xF1, 0x04, 0x9B, 0xE7, 0x3C,
};

static int img_read(void *ctx, void *buf, uint64_t sector, uint32_t count)
{
    (void)ctx;
    uint64_t off = sector * 0x200, n = (uint64_t)count * 0x200;
    if (off + n > IMG_SIZE)
        return -1;
    memcpy(buf, g_img_buf + off, n);
    return 0;
}

/* XCI with header at 0 (CardInfo encrypted as on a real card) and the card
 * certificate at 0x7000, blanked unless with_cert. */
static void make_image(const uint8_t cardinfo[0x70], int with_cert)
{
    memset(g_img_buf, 0, IMG_SIZE);
    uint8_t *h = g_img_buf + 0x100, iv[16];
    memcpy(h, "HEAD", 4);
    h[0x0C] = 0x02; /* KEK index */
    h[0x0D] = 0xE0; /* capacity */
    for (int i = 0; i < 16; i++)
        h[0x20 + i] = (uint8_t)(0x40 + i * 3);
    for (int i = 0; i < 16; i++)
        iv[i] = h[0x2F - i];
    gc_aes128_cbc_encrypt(k_header_key, iv, cardinfo, h + 0x90, 0x70);
    uint8_t *cert = g_img_buf + 0x7000;
    memset(cert, 0xFF, 0x200);
    if (with_cert) {
        for (int i = 0; i < 0x100; i++)
            cert[i] = (uint8_t)(i * 7 + 3);
        memset(cert + 0x100, 0, 0x100);
        memcpy(cert + 0x100, "CERT", 4);
        cert[0x108] = 0x02;
        memset(cert + 0x110, 0x9C, 0x10);
    }
}

/* sub_1902C0 on FS's side. */
static int fs_mac_ok(const gc_card_secrets_t *k, const uint8_t *data, size_t len,
                     const uint8_t mac[32])
{
    uint8_t msg[64], want[32];
    gc_sha256(data, len, msg);
    memcpy(msg + 32, k->mac_ctr, 16);
    memcpy(msg + 48, k->mac_salt, 16);
    gc_hmac_sha256(k->mac_key, 32, msg, sizeof(msg), want);
    return memcmp(want, mac, 32) == 0;
}

/* sub_190270: the reply counter in use is copied out, then advanced (LE). */
static void fs_next_reply(uint8_t used[16], uint8_t ctr[16])
{
    memcpy(used, ctr, 16);
    for (int i = 0; i < 16; i++)
        if (++ctr[i] != 0)
            break;
}

static uint32_t fs_id_read(gc_asic_t *a, fs_session_t *s, uint8_t cmd)
{
    uint8_t hdr[GC_OP_SIZE], frame[0x200];
    hdr_for(hdr, 0x10);
    hdr[1] = 1;
    hdr[8] = cmd;
    if (fs_read_hdr(a, s, hdr, frame, sizeof(frame), 1))
        return 0xDEADBEEF;
    return gc_rd32(frame);
}

static void test_activation(int with_cert)
{
    static gc_asic_t a;
    static gc_image_t img;
    fs_session_t s;
    uint8_t dev[32], cardinfo[0x70];
    const char *tag = with_cert ? "genuine cert" : "blank cert";
    char name[96];
#define CHK(what, cond) do { snprintf(name, sizeof(name), "%s: %s", tag, what); chk(name, cond); } while (0)

    for (size_t i = 0; i < sizeof(cardinfo); i++)
        cardinfo[i] = (uint8_t)(i ^ 0x5A);
    make_image(cardinfo, with_cert);
    gc_asic_init(&a, rng, NULL);
    gc_bdev_t bdev = { img_read, NULL };
    gc_run_t run = { 0, IMG_SIZE / 0x200 };
    CHK("attach", gc_image_init(&img, &bdev, &run, 1, IMG_SIZE) == 0 && gc_asic_attach(&a, &img) == 0);
    session(&s, GC_LINK_CTR);
    CHK("challenge", fs_challenge(&a, &s, 1, dev) == 0);

    uint8_t mac_key[32], salt[16], reply_ctr[16], used[16];
    for (int i = 0; i < 32; i++)
        mac_key[i] = (uint8_t)(0xA5 ^ i * 11);
    for (int i = 0; i < 16; i++) {
        salt[i] = (uint8_t)(0x30 + i);
        reply_ctr[i] = i == 0 ? 0xFF : 0; /* carries on the first advance */
    }
    gc_card_secrets_t k = { mac_key, salt, used, k_header_key };
    g_secrets = &k;

    /* sub_186ED0: ID1, page 0, GetCardHeader. */
    uint32_t id1 = fs_id_read(&a, &s, 0x56);
    uint8_t hdr[GC_OP_SIZE], page[0x200], page_hash[32];
    hdr_for(hdr, 0x10);
    hdr[1] = 3;
    gc_wr32(hdr + 4, 1);
    hdr[8] = 0x5B;
    gc_wr32be(hdr + 9, 0);
    CHK("page 0 read", fs_read_hdr(&a, &s, hdr, page, sizeof(page), 1) == 0 &&
                       memcmp(page, g_img_buf, 0x200) == 0);
    gc_sha256(page + 0x100, 0x100, page_hash);

    /* Bulk read as sub_18B560 issues it: one op for many pages (FS read
     * 0x8E at once on the console), served whole, no 8-page cap. */
    static uint8_t bulk[0x30 * 0x200];
    hdr_for(hdr, 0x10);
    hdr[1] = 3;
    gc_wr32(hdr + 4, 0x30);
    hdr[8] = 0x5B;
    gc_wr32be(hdr + 9, 0x08);
    CHK("0x30-page read in one op", fs_read_hdr(&a, &s, hdr, bulk, sizeof(bulk), 1) == 0 &&
                                    a.l3.pending_len == sizeof(bulk) &&
                                    memcmp(bulk, g_img_buf + 0x08 * 0x200, sizeof(bulk)) == 0);
    hdr_for(hdr, 0x10);
    hdr[1] = 3;
    gc_wr32(hdr + 4, 0x10);
    hdr[8] = 0x5B;
    gc_wr32be(hdr + 9, IMG_SIZE / 0x200 - 8);
    CHK("read past the image end fails", fs_read_hdr(&a, &s, hdr, bulk, 0x10 * 0x200, 1) != 0);

    fs_next_reply(used, reply_ctr);
    uint8_t ch[0x200], h2[0x100], iv[16], h2_hash[32];
    CHK("GetCardHeader", fs_read(&a, &s, 0x0E, ch, sizeof(ch), 1) == 0);
    CHK("GetCardHeader MAC (sub_1902C0)", fs_mac_ok(&k, ch, 0x1E0, ch + 0x1E0));
    CHK("GetCardHeader CardId1", gc_rd32(ch + 4) == id1);
    CHK("CardInfo served in plaintext", memcmp(ch + 8 + 0x90, cardinfo, sizeof(cardinfo)) == 0);
    memcpy(h2, ch + 8, sizeof(h2)); /* sub_18FE60, then SHA-256 vs the page */
    for (int i = 0; i < 16; i++)
        iv[i] = h2[0x2F - i];
    gc_aes128_cbc_encrypt(k_header_key, iv, h2 + 0x90, h2 + 0x90, 0x70);
    gc_sha256(h2, sizeof(h2), h2_hash);
    CHK("header hash matches page read", memcmp(h2_hash, page_hash, 32) == 0);
    uint32_t id2 = fs_id_read(&a, &s, 0x28);

    /* sub_187930: CardKeyArea. */
    uint8_t prev[16];
    memcpy(prev, used, 16);
    fs_next_reply(used, reply_ctr);
    static uint8_t ka[0x800];
    CHK("CardKeyArea", fs_read(&a, &s, 0x0F, ka, sizeof(ka), 1) == 0);
    CHK("CardKeyArea MAC (sub_1902C0)", fs_mac_ok(&k, ka + 0x200, 0x600, ka + 0x1E0));
    k.mac_ctr = prev;
    CHK("stale reply counter rejected", !fs_mac_ok(&k, ka + 0x200, 0x600, ka + 0x1E0));
    k.mac_ctr = used;
    CHK("KEK index == header 0x10C & 0xF", ka[0x308] == (g_img_buf[0x10C] & 0x0F));
    CHK("CardId1 == GetCardHeader (0x1878D0)", memcmp(ka + 8, ch + 4, 4) == 0);
    CHK("CardId2 == ID2 read (0x1878E4)", gc_rd32(ka + 0xC) == id2);
    int zero = 1;
    for (size_t i = 0x63C; i < sizeof(ka); i++)
        zero = zero && ka[i] == 0;
    CHK("zero after InitialData challenge", zero);
    if (with_cert)
        CHK("image certificate served", a.l3.card_cert_genuine &&
                                       memcmp(ka + 0x200, g_img_buf + 0x7000, 0x200) == 0);
    else
        CHK("stand-in certificate served", !a.l3.card_cert_genuine &&
                                          memcmp(ka + 0x300, "CERT", 4) == 0);
    g_secrets = NULL;
#undef CHK
}

int main(void)
{
    gc_asic_t a;
    fs_session_t s;
    uint8_t dev[32];

    /* Keyed session (FS sets link[4] after sub_18FF40): CBC copy-out. */
    gc_asic_init(&a, rng, NULL);
    session(&s, GC_LINK_CBC);
    chk("cbc: challenge passes when sealed", fs_challenge(&a, &s, 1, dev) == 0);
    chk("cbc: op 6 delivers the device random", memcmp(dev, a.l3.asic_rand, 32) == 0);

    /* The 2002-2655 boot: right answer, unsealed frame. */
    gc_asic_init(&a, rng, NULL);
    session(&s, GC_LINK_CBC);
    chk("cbc: unsealed answer fails with 2655", fs_challenge(&a, &s, 0, dev) == 2655);

    /* The answer itself is pinned: SHA-256(op 8), not the raw challenge. */
    gc_asic_init(&a, rng, NULL);
    session(&s, GC_LINK_PLAIN);
    chk("plain: challenge passes", fs_challenge(&a, &s, 1, dev) == 0);

    /* Secure mode: CTR stream over whole frames, counter carried across ops. */
    gc_asic_init(&a, rng, NULL);
    session(&s, GC_LINK_CTR);
    chk("ctr: challenge passes when sealed", fs_challenge(&a, &s, 1, dev) == 0);
    chk("ctr: op 6 delivers the device random", memcmp(dev, a.l3.asic_rand, 32) == 0);
    uint8_t regs[0x30];
    chk("ctr: read after the exchange", fs_read(&a, &s, 0x0C, regs, sizeof(regs), 1) == 0);
    chk("ctr: register 1 intact", gc_rd32(regs + 4) == 0x00A10011);
    /* WriteRegister as sub_18CAA0/sub_18AEB0 send it: mode 1, the 4-byte
     * value as the logical length, register byte offset in header +4. */
    {
        uint8_t hdr[GC_OP_SIZE], val[4];
        uint32_t st = 0xFFFF;
        hdr_for(hdr, 0x0B);
        gc_wr32(hdr + 4, 0x1C);
        gc_wr32(val, 100);
        chk("ctr: WriteRegister with len 4", gc_asic_exec(&a, &st, val, sizeof(val), hdr) == 0 && st == 0);
        chk("ctr: read back", fs_read(&a, &s, 0x0C, regs, sizeof(regs), 1) == 0);
        chk("ctr: register 7 written", gc_rd32(regs + 0x1C) == 100);
        chk("ctr: register 0 status clear", gc_rd32(regs) == 0);
    }

    /* CBC with a logical length that is not a multiple of 16: FS decrypts the
     * tail block on its own from the IV. */
    session(&s, GC_LINK_CBC);
    uint8_t frame[FRAME], want[40], got[40];
    for (size_t i = 0; i < sizeof(want); i++)
        want[i] = (uint8_t)(i * 13 + 1);
    memset(frame, 0xEE, sizeof(frame));
    memcpy(frame, want, sizeof(want));
    gc_link_seal(GC_LINK_CBC, s.key, s.iv, frame, sizeof(frame), sizeof(want));
    fs_copy_out(&s, got, sizeof(got), frame, sizeof(frame));
    chk("cbc: unaligned tail block", memcmp(got, want, sizeof(want)) == 0);

    /* Activation: IDs, GetCardHeader and CardKeyArea as FS checks them. */
    test_activation(0);
    test_activation(1);

    if (fails)
        printf("%d failure(s)\n", fails);
    else
        printf("PASS\n");
    return fails ? 1 : 0;
}
