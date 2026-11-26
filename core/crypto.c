#include "crypto.h"

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t ror32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(gc_sha256_t *s, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = gc_rd32be(p + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void gc_sha256_init(gc_sha256_t *s)
{
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(s->h, iv, sizeof(iv));
    s->total = 0;
    s->buflen = 0;
}

void gc_sha256_update(gc_sha256_t *s, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    s->total += len;
    if (s->buflen) {
        size_t take = 64 - s->buflen;
        if (take > len)
            take = len;
        memcpy(s->buf + s->buflen, p, take);
        s->buflen += take;
        p += take;
        len -= take;
        if (s->buflen == 64) {
            sha256_block(s, s->buf);
            s->buflen = 0;
        }
    }
    while (len >= 64) {
        sha256_block(s, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(s->buf, p, len);
        s->buflen = len;
    }
}

void gc_sha256_final(gc_sha256_t *s, uint8_t out[32])
{
    uint64_t bits = s->total * 8;
    uint8_t pad[72] = {0x80};
    size_t padlen = (s->buflen < 56) ? (56 - s->buflen) : (120 - s->buflen);
    gc_sha256_update(s, pad, padlen);
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++)
        lenbuf[i] = (uint8_t)(bits >> (56 - 8 * i));
    gc_sha256_update(s, lenbuf, 8);
    for (int i = 0; i < 8; i++)
        gc_wr32be(out + 4 * i, s->h[i]);
}

void gc_sha256(const void *data, size_t len, uint8_t out[32])
{
    gc_sha256_t s;
    gc_sha256_init(&s);
    gc_sha256_update(&s, data, len);
    gc_sha256_final(&s, out);
}

void gc_hmac_sha256(const uint8_t *key, size_t keylen,
                    const void *msg, size_t msglen, uint8_t out[32])
{
    uint8_t k[64] = {0};
    if (keylen > 64)
        gc_sha256(key, keylen, k);
    else
        memcpy(k, key, keylen);

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    gc_sha256_t s;
    uint8_t inner[32];
    gc_sha256_init(&s);
    gc_sha256_update(&s, ipad, 64);
    gc_sha256_update(&s, msg, msglen);
    gc_sha256_final(&s, inner);
    gc_sha256_init(&s);
    gc_sha256_update(&s, opad, 64);
    gc_sha256_update(&s, inner, 32);
    gc_sha256_final(&s, out);
}

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t ISBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static inline uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        b >>= 1;
        a = xtime(a);
    }
    return p;
}

void gc_aes128_init(gc_aes128_t *a, const uint8_t key[16])
{
    uint32_t w[44];
    for (int i = 0; i < 4; i++)
        w[i] = gc_rd32be(key + 4 * i);
    for (int i = 4; i < 44; i++) {
        uint32_t t = w[i - 1];
        if ((i & 3) == 0) {
            t = (t << 8) | (t >> 24); /* RotWord */
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) | SBOX[t & 0xff];
            t ^= (uint32_t)RCON[i / 4] << 24;
        }
        w[i] = w[i - 4] ^ t;
    }
    for (int i = 0; i < 44; i++)
        gc_wr32be(a->rk + 4 * i, w[i]);
}

static void add_rk(uint8_t s[16], const uint8_t *rk) { for (int i = 0; i < 16; i++) s[i] ^= rk[i]; }
static void sub_bytes(uint8_t s[16]) { for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]]; }
static void inv_sub_bytes(uint8_t s[16]) { for (int i = 0; i < 16; i++) s[i] = ISBOX[s[i]]; }

/* state index = 4*col + row */
static void shift_rows(uint8_t s[16])
{
    uint8_t t[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            t[4 * c + r] = s[4 * ((c + r) & 3) + r];
    memcpy(s, t, 16);
}

static void inv_shift_rows(uint8_t s[16])
{
    uint8_t t[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            t[4 * c + r] = s[4 * ((c - r + 4) & 3) + r];
    memcpy(s, t, 16);
}

static void mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        p[0] ^= t ^ xtime(a0 ^ a1);
        p[1] ^= t ^ xtime(a1 ^ a2);
        p[2] ^= t ^ xtime(a2 ^ a3);
        p[3] ^= t ^ xtime(a3 ^ a0);
    }
}

static void inv_mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = (uint8_t)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
        p[1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
        p[2] = (uint8_t)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
        p[3] = (uint8_t)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
    }
}

void gc_aes128_encrypt_block(const gc_aes128_t *a, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    memcpy(s, in, 16);
    add_rk(s, a->rk);
    for (int r = 1; r <= 9; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_rk(s, a->rk + 16 * r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_rk(s, a->rk + 160);
    memcpy(out, s, 16);
}

void gc_aes128_decrypt_block(const gc_aes128_t *a, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    memcpy(s, in, 16);
    add_rk(s, a->rk + 160);
    for (int r = 9; r >= 1; r--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_rk(s, a->rk + 16 * r);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_rk(s, a->rk);
    memcpy(out, s, 16);
}

void gc_aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len)
{
    gc_aes128_t a;
    gc_aes128_init(&a, key);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16];
        for (int i = 0; i < 16; i++)
            blk[i] = in[off + i] ^ prev[i];
        gc_aes128_encrypt_block(&a, blk, out + off);
        memcpy(prev, out + off, 16);
    }
}

void gc_aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len)
{
    gc_aes128_t a;
    gc_aes128_init(&a, key);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16], cblk[16];
        memcpy(cblk, in + off, 16); /* save before writing: in may alias out */
        gc_aes128_decrypt_block(&a, cblk, blk);
        for (int i = 0; i < 16; i++)
            out[off + i] = blk[i] ^ prev[i];
        memcpy(prev, cblk, 16);
    }
}

void gc_aes128_ctr(const uint8_t key[16], uint8_t ctr[16],
                   const uint8_t *in, uint8_t *out, size_t len)
{
    gc_aes128_t a;
    gc_aes128_init(&a, key);
    uint8_t ks[16];
    for (size_t off = 0; off < len; off += 16) {
        gc_aes128_encrypt_block(&a, ctr, ks);
        size_t n = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < n; i++)
            out[off + i] = in[off + i] ^ ks[i];
        for (int i = 15; i >= 0; i--)
            if (++ctr[i] != 0)
                break;
    }
}

void gc_aes128_xts(const uint8_t key[32], const uint8_t tweak[16], uint8_t *buf,
                   size_t len, bool encrypt)
{
    gc_aes128_t data, tk;
    gc_aes128_init(&data, key);
    gc_aes128_init(&tk, key + 16);
    uint8_t t[16];
    gc_aes128_encrypt_block(&tk, tweak, t);
    for (size_t off = 0; off + 16 <= len; off += 16) {
        uint8_t b[16];
        for (int i = 0; i < 16; i++)
            b[i] = buf[off + i] ^ t[i];
        if (encrypt)
            gc_aes128_encrypt_block(&data, b, b);
        else
            gc_aes128_decrypt_block(&data, b, b);
        for (int i = 0; i < 16; i++)
            buf[off + i] = b[i] ^ t[i];
        /* t *= alpha in GF(2^128), little-endian bytes. */
        uint8_t carry = 0;
        for (int i = 0; i < 16; i++) {
            const uint8_t next = t[i] >> 7;
            t[i] = (uint8_t)(t[i] << 1 | carry);
            carry = next;
        }
        if (carry)
            t[0] ^= 0x87;
    }
}

#define RSA_LIMBS 32 /* 32 * 64 = 2048 bits */

typedef struct { uint64_t v[RSA_LIMBS]; } bi_t;

static int bi_cmp(const bi_t *a, const bi_t *b)
{
    for (int i = RSA_LIMBS - 1; i >= 0; i--)
        if (a->v[i] != b->v[i])
            return a->v[i] > b->v[i] ? 1 : -1;
    return 0;
}

static void bi_sub(bi_t *a, const bi_t *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < RSA_LIMBS; i++) {
        unsigned __int128 cur = (unsigned __int128)a->v[i] - b->v[i] - borrow;
        a->v[i] = (uint64_t)cur;
        borrow = (uint64_t)(cur >> 64) & 1;
    }
}

static void bi_dbl_mod(bi_t *a, const bi_t *n)
{
    uint64_t carry = 0;
    for (int i = 0; i < RSA_LIMBS; i++) {
        uint64_t nv = (a->v[i] << 1) | carry;
        carry = a->v[i] >> 63;
        a->v[i] = nv;
    }
    if (carry || bi_cmp(a, n) >= 0)
        bi_sub(a, n);
}

/* out = a*b*R^-1 mod n, R = 2^2048. Aliasing of out with a or b is safe. */
static void mont_mul(bi_t *out, const bi_t *a, const bi_t *b, const bi_t *n, uint64_t n0inv)
{
    uint64_t t[RSA_LIMBS + 2] = {0};
    for (int i = 0; i < RSA_LIMBS; i++) {
        uint64_t c = 0;
        for (int j = 0; j < RSA_LIMBS; j++) {
            unsigned __int128 s = (unsigned __int128)a->v[j] * b->v[i] + t[j] + c;
            t[j] = (uint64_t)s;
            c = (uint64_t)(s >> 64);
        }
        unsigned __int128 s2 = (unsigned __int128)t[RSA_LIMBS] + c;
        t[RSA_LIMBS] = (uint64_t)s2;
        t[RSA_LIMBS + 1] = (uint64_t)(s2 >> 64);

        uint64_t m = t[0] * n0inv;
        unsigned __int128 s3 = (unsigned __int128)m * n->v[0] + t[0];
        c = (uint64_t)(s3 >> 64);
        for (int j = 1; j < RSA_LIMBS; j++) {
            unsigned __int128 s4 = (unsigned __int128)m * n->v[j] + t[j] + c;
            t[j - 1] = (uint64_t)s4;
            c = (uint64_t)(s4 >> 64);
        }
        unsigned __int128 s5 = (unsigned __int128)t[RSA_LIMBS] + c;
        t[RSA_LIMBS - 1] = (uint64_t)s5;
        t[RSA_LIMBS] = t[RSA_LIMBS + 1] + (uint64_t)(s5 >> 64);
    }
    bi_t r;
    memcpy(r.v, t, sizeof(r.v));
    if (t[RSA_LIMBS] || bi_cmp(&r, n) >= 0)
        bi_sub(&r, n);
    *out = r;
}

static void bi_from_bytes(bi_t *a, const uint8_t in[256])
{
    for (int i = 0; i < RSA_LIMBS; i++)
        a->v[RSA_LIMBS - 1 - i] = gc_rd64be(in + 8 * i);
}

static void bi_to_bytes(const bi_t *a, uint8_t out[256])
{
    for (int i = 0; i < RSA_LIMBS; i++)
        for (int k = 0; k < 8; k++)
            out[8 * i + k] = (uint8_t)(a->v[RSA_LIMBS - 1 - i] >> (56 - 8 * k));
}

static void rsa_op(const uint8_t n_bytes[256], const uint8_t *exp, size_t explen,
                   const bi_t *m, bi_t *out)
{
    bi_t n;
    bi_from_bytes(&n, n_bytes);
    uint64_t n0inv;
    {
        uint64_t inv = 1;
        for (int i = 0; i < 6; i++)
            inv *= 2 - n.v[0] * inv; /* n^-1 mod 2^64 */
        n0inv = (uint64_t)(0 - inv);
    }
    bi_t base = *m;
    for (int i = 0; i < 2048; i++) /* base * R mod n */
        bi_dbl_mod(&base, &n);

    size_t nbits = explen * 8;
    size_t first = 0;
    while (first < nbits && !((exp[first >> 3] >> (7 - (first & 7))) & 1))
        first++;
    if (first == nbits) { /* exp == 0 */
        memset(out, 0, sizeof(*out));
        return;
    }
    bi_t acc = base;
    for (size_t bit = first + 1; bit < nbits; bit++) {
        mont_mul(&acc, &acc, &acc, &n, n0inv);
        if ((exp[bit >> 3] >> (7 - (bit & 7))) & 1)
            mont_mul(&acc, &acc, &base, &n, n0inv);
    }
    bi_t one;
    memset(&one, 0, sizeof(one));
    one.v[0] = 1;
    mont_mul(out, &acc, &one, &n, n0inv); /* out of Montgomery form */
}

int gc_rsa2048_raw(const uint8_t n[256], const uint8_t *exp, size_t explen,
                   const uint8_t in[256], uint8_t out[256])
{
    if (!exp || explen == 0 || explen > 256)
        return -1;
    bi_t m, c;
    bi_from_bytes(&m, in);
    rsa_op(n, exp, explen, &m, &c);
    bi_to_bytes(&c, out);
    return 0;
}

static void mgf1_sha256(const uint8_t *seed, size_t slen, uint8_t *out, size_t olen)
{
    uint8_t buf[256 + 4];
    memcpy(buf, seed, slen);
    size_t done = 0;
    uint32_t ctr = 0;
    while (done < olen) {
        buf[slen] = (uint8_t)(ctr >> 24);
        buf[slen + 1] = (uint8_t)(ctr >> 16);
        buf[slen + 2] = (uint8_t)(ctr >> 8);
        buf[slen + 3] = (uint8_t)ctr;
        uint8_t h[32];
        gc_sha256(buf, slen + 4, h);
        size_t n = olen - done < 32 ? olen - done : 32;
        memcpy(out + done, h, n);
        done += n;
        ctr++;
    }
}

int gc_rsa2048_oaep_sha256_encrypt(const uint8_t n[256], const uint8_t *msg,
                                   size_t mlen, const uint8_t seed[32],
                                   uint8_t out[256])
{
    const size_t k = 256, hlen = 32;
    if (mlen > k - 2 * hlen - 2)
        return -1;

    uint8_t lhash[32], db[223], em[256];
    gc_sha256("", 0, lhash);

    size_t ps = k - mlen - 2 * hlen - 2;
    size_t o = 0;
    memcpy(db + o, lhash, hlen); o += hlen;
    memset(db + o, 0, ps); o += ps;
    db[o++] = 0x01;
    memcpy(db + o, msg, mlen); o += mlen;

    uint8_t dbmask[223], seedmask[32];
    mgf1_sha256(seed, 32, dbmask, sizeof(dbmask));
    for (size_t i = 0; i < sizeof(db); i++)
        db[i] ^= dbmask[i];
    mgf1_sha256(db, sizeof(db), seedmask, sizeof(seedmask));

    em[0] = 0x00;
    for (int i = 0; i < 32; i++)
        em[1 + i] = seed[i] ^ seedmask[i];
    memcpy(em + 33, db, sizeof(db));

    static const uint8_t pubexp[3] = {0x01, 0x00, 0x01};
    return gc_rsa2048_raw(n, pubexp, sizeof(pubexp), em, out);
}
