/* Control data from an XCI (core/nca.c): XTS, a synthetic card with test
 * keys, and the key-source scan over FS 23.5.0's read-only data. Real
 * Nintendo keys never enter this test; on the console they come from spl. */
#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"
#include "nca.h"

static int fails;

static void chk(const char *name, int cond)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        fails++;
}

static void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void wr64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

static int unhex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* IEEE 1619-2007 XTS-AES-128 vectors 1 and 2 (data unit 0 / 0x3333333333). */
static void test_xts(void)
{
    uint8_t key[32] = { 0 }, tweak[16] = { 0 }, buf[32] = { 0 }, want[32];
    unhex("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e", want, 32);
    gc_aes128_xts(key, tweak, buf, 32, true);
    chk("xts vector 1 encrypt", memcmp(buf, want, 32) == 0);
    gc_aes128_xts(key, tweak, buf, 32, false);
    chk("xts vector 1 decrypt", buf[0] == 0 && memcmp(buf, buf + 1, 31) == 0);

    memset(key, 0x11, 16);
    memset(key + 16, 0x22, 16);
    memset(buf, 0x44, 32);
    for (int i = 0; i < 5; i++)
        tweak[i] = 0x33;
    unhex("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0", want, 32);
    gc_aes128_xts(key, tweak, buf, 32, true);
    chk("xts vector 2 encrypt", memcmp(buf, want, 32) == 0);

    uint8_t t[16];
    gc_nca_tweak(0x0102, t);
    chk("nca tweak is big-endian", t[15] == 0x02 && t[14] == 0x01 && t[0] == 0);
}

#define GEN 5 /* NCA key generation; master key revision 4 */
static uint8_t g_header_key[32], g_kaek[16];
static int g_unwrap_calls;

static int unwrap(void *ctx, uint8_t generation, const uint8_t in[16], uint8_t out[16])
{
    (void)ctx;
    g_unwrap_calls++;
    if (generation != GEN)
        return -1;
    gc_aes128_t a;
    gc_aes128_init(&a, g_kaek);
    gc_aes128_decrypt_block(&a, in, out);
    return 0;
}

typedef struct {
    uint8_t *p;
    size_t len;
} buf_t;

static void put(buf_t *b, size_t off, const void *src, size_t n)
{
    if (off + n > b->len) {
        b->p = realloc(b->p, off + n);
        memset(b->p + b->len, 0, off + n - b->len);
        b->len = off + n;
    }
    memcpy(b->p + off, src, n);
}

static const uint8_t ICON_JP[100] = { 0xFF, 0xD8, 'j', 'p' };
static uint8_t ICON_EN[300] = { 0xFF, 0xD8, 'e', 'n' };

/* A Control NCA whose RomFS holds control.nacp, icon_Japanese.dat and
 * icon_AmericanEnglish.dat; or a Program NCA (type 0) with the same body. */
static buf_t make_nca(uint8_t type, uint64_t program_id, const char *title)
{
    /* RomFS: header, file meta table, data. */
    buf_t rom = { 0 };
    uint8_t hdr[0x50] = { 0 };
    const struct { const char *name; size_t off, size; } files[] = {
        { "icon_Japanese.dat", 0x4000, sizeof(ICON_JP) },
        { "control.nacp", 0, 0x4000 },
        { "icon_AmericanEnglish.dat", 0x4100, sizeof(ICON_EN) },
    };
    size_t meta = 0x200, mp = 0;
    for (size_t i = 0; i < 3; i++) {
        uint8_t e[0x60] = { 0 };
        const uint32_t nl = (uint32_t)strlen(files[i].name);
        wr32(e + 0x4, 0xFFFFFFFF);
        wr64(e + 0x8, files[i].off);
        wr64(e + 0x10, files[i].size);
        wr32(e + 0x1C, nl);
        memcpy(e + 0x20, files[i].name, nl);
        const size_t step = 0x20 + ((nl + 3u) & ~3u);
        put(&rom, meta + mp, e, step);
        mp += step;
    }
    wr64(hdr + 0x00, 0x50);
    wr64(hdr + 0x38, meta);
    wr64(hdr + 0x40, mp);
    wr64(hdr + 0x48, 0x1000);
    put(&rom, 0, hdr, sizeof(hdr));
    uint8_t nacp[0x4000] = { 0 };
    memcpy(nacp + 0x300, "Japanese name", 13); /* entry 1; entry 0 wins */
    memcpy(nacp, title, strlen(title));
    memcpy(nacp + 0x200, "Test Publisher", 14);
    put(&rom, 0x1000, nacp, sizeof(nacp));
    put(&rom, 0x1000 + 0x4000, ICON_JP, sizeof(ICON_JP));
    put(&rom, 0x1000 + 0x4100, ICON_EN, sizeof(ICON_EN));

    /* NCA: 0xC00 header, section 0 at 0xC00: 0x4000 of hash levels, then
     * the RomFS (IVFC level 5). */
    const size_t start = 0xC00, level5 = 0x4000;
    const size_t end = (start + level5 + rom.len + 0x1FF) & ~(size_t)0x1FF;
    buf_t nca = { 0 };
    uint8_t h[0xC00] = { 0 };
    memcpy(h + 0x200, "NCA3", 4);
    h[0x204] = 1;          /* game card */
    h[0x205] = type;
    h[0x206] = 2;          /* old field; the larger generation counts */
    h[0x220] = GEN;
    wr64(h + 0x208, end);
    wr64(h + 0x210, program_id);
    wr32(h + 0x240, (uint32_t)(start / 0x200));
    wr32(h + 0x244, (uint32_t)(end / 0x200));
    uint8_t content_key[16];
    for (int i = 0; i < 16; i++)
        content_key[i] = (uint8_t)(0xA0 + i + program_id);
    gc_aes128_t a;
    gc_aes128_init(&a, g_kaek);
    gc_aes128_encrypt_block(&a, content_key, h + 0x300 + 0x20);
    uint8_t *fs = h + 0x400;
    fs[2] = 0;             /* RomFS */
    fs[3] = 3;             /* IVFC */
    fs[4] = 3;             /* AES-CTR */
    memcpy(fs + 8, "IVFC", 4);
    wr64(fs + 8 + 0x10 + 5 * 0x18, level5);
    wr64(fs + 8 + 0x10 + 5 * 0x18 + 8, rom.len);
    wr64(fs + 0x140, 0x0000000500000007ull); /* generation 7, secure value 5 */

    uint8_t *body = calloc(1, end - start);
    memset(body, 0x5A, level5);
    memcpy(body + level5, rom.p, rom.len);
    uint8_t ctr[16] = { 0 };
    for (int i = 0; i < 8; i++)
        ctr[i] = fs[0x140 + 7 - i];
    for (int i = 0; i < 8; i++)
        ctr[15 - i] = (uint8_t)((start >> 4) >> (8 * i));
    gc_aes128_ctr(content_key, ctr, body, body, end - start);
    put(&nca, start, body, end - start);
    free(body);
    free(rom.p);

    for (uint64_t s = 0; s < 6; s++) {
        uint8_t tweak[16];
        gc_nca_tweak(s, tweak);
        gc_aes128_xts(g_header_key, tweak, h + s * 0x200, 0x200, true);
    }
    put(&nca, 0, h, sizeof(h));
    return nca;
}

/* HFS0 over the given files; `extra` is added to the last entry's size to
 * mimic a trimmed dump whose partition ends past the file. */
static buf_t make_hfs0(const char *const *names, const buf_t *files, size_t n, uint64_t extra)
{
    char strtab[256] = { 0 };
    size_t sl = 0;
    uint32_t name_off[8];
    for (size_t i = 0; i < n; i++) {
        name_off[i] = (uint32_t)sl;
        memcpy(strtab + sl, names[i], strlen(names[i]) + 1);
        sl += strlen(names[i]) + 1;
    }
    sl = (sl + 0xF) & ~(size_t)0xF;
    const size_t data = 0x10 + n * 0x40 + sl;
    buf_t b = { 0 };
    uint8_t h[0x10] = { 'H', 'F', 'S', '0' };
    wr32(h + 4, (uint32_t)n);
    wr32(h + 8, (uint32_t)sl);
    put(&b, 0, h, sizeof(h));
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t e[0x40] = { 0 };
        wr64(e, off);
        wr64(e + 8, files[i].len + (i + 1 == n ? extra : 0));
        wr32(e + 0x10, name_off[i]);
        put(&b, 0x10 + i * 0x40, e, sizeof(e));
        put(&b, data + off, files[i].p, files[i].len);
        off += files[i].len;
    }
    put(&b, 0x10 + n * 0x40, strtab, sl);
    return b;
}

static buf_t g_img;

static int mem_read(void *ctx, void *buf, uint64_t sector, uint32_t count)
{
    (void)ctx;
    const uint64_t off = sector * GC_SECTOR_SIZE, n = (uint64_t)count * GC_SECTOR_SIZE;
    memset(buf, 0, (size_t)n);
    if (off < g_img.len)
        memcpy(buf, g_img.p + off, (size_t)(off + n <= g_img.len ? n : g_img.len - off));
    return 0;
}

static void test_card(void)
{
    for (int i = 0; i < 32; i++)
        g_header_key[i] = (uint8_t)(0x31 * i + 7);
    for (int i = 0; i < 16; i++)
        g_kaek[i] = (uint8_t)(0x55 ^ i);
    for (size_t i = 4; i < sizeof(ICON_EN); i++)
        ICON_EN[i] = (uint8_t)i;

    const char *sec_names[] = { "prog.nca", "upd.nca", "base.nca", "meta.cnmt.nca" };
    buf_t sec_files[4] = {
        make_nca(0, 0x0100000000010000ull, "Program"),
        make_nca(2, 0x0100000000010800ull, "Update Title"),
        make_nca(2, 0x0100000000010000ull, "Base Title"),
        { (uint8_t *)"not an nca", 10 },
    };
    buf_t secure = make_hfs0(sec_names, sec_files, 4, 0);
    const char *root_names[] = { "update", "secure" };
    buf_t root_files[2] = { { NULL, 0 }, secure };
    buf_t root = make_hfs0(root_names, root_files, 2, 0x600);

    /* A dump: CardHeader at 0, root HFS0 at 0x1000. */
    uint8_t ch[0x200] = { 0 };
    memcpy(ch + 0x100, "HEAD", 4);
    wr64(ch + 0x130, 0x1000);
    wr64(ch + 0x138, 0x200);
    put(&g_img, 0, ch, sizeof(ch));
    put(&g_img, 0x1000, root.p, root.len);
    put(&g_img, ((g_img.len + 0x1FF) & ~(size_t)0x1FF) - 1, "", 1);

    gc_bdev_t dev = { mem_read, NULL };
    gc_run_t run = { 0, g_img.len / GC_SECTOR_SIZE };
    gc_image_t img;
    gc_xci_t x;
    chk("image", gc_image_init(&img, &dev, &run, 1, g_img.len) == 0);
    chk("dump header at 0", gc_xci_open(&x, &img) == 0 && x.pfs_off == 0x1000);

    gc_nca_keys_t keys = { { 0 }, unwrap, NULL };
    memcpy(keys.header_key, g_header_key, 32);
    static uint8_t icon[0x20000];
    gc_control_t c;
    int rc = gc_xci_read_control(&x, &keys, &c, icon, sizeof(icon));
    chk("control read", rc == 0);
    chk("base application picked", c.program_id == 0x0100000000010000ull && strcmp(c.title, "Base Title") == 0);
    chk("publisher", strcmp(c.publisher, "Test Publisher") == 0);
    chk("American English icon", c.icon_size == sizeof(ICON_EN) && memcmp(icon, ICON_EN, sizeof(ICON_EN)) == 0);
    chk("key area unwrapped with the larger generation field", g_unwrap_calls == 1);

    chk("small icon buffer refused", gc_xci_read_control(&x, &keys, &c, icon, 100) == GC_NCA_ERR_NO_ICON);

    keys.header_key[0] ^= 1;
    chk("wrong header key: no control", gc_xci_read_control(&x, &keys, &c, icon, sizeof(icon)) == GC_NCA_ERR_NO_CONTROL);

    for (size_t i = 0; i < 3; i++)
        free(sec_files[i].p);
    free(secure.p);
    free(root.p);
    free(g_img.p);
}

#define FS_ELF "fw_elf_kip_23.5.0/0100000000000000_FS.elf"
#define RODATA_OFF 0x1e0000
#define RODATA_SIZE 0x6858c

static void test_key_sources(void)
{
    FILE *f = fopen(FS_ELF, "rb");
    if (!f) {
        printf("skip key sources (%s not present)\n", FS_ELF);
        return;
    }
    uint8_t *ro = malloc(RODATA_SIZE);
    const int got = fseek(f, RODATA_OFF, SEEK_SET) == 0 && fread(ro, 1, RODATA_SIZE, f) == RODATA_SIZE;
    fclose(f);
    chk("FS rodata read", got);
    gc_key_sources_t s;
    const unsigned found = gc_find_key_sources(ro, RODATA_SIZE, gc_sha256, &s);
    chk("all three sources found", found == GC_KEYSRC_ALL);
    /* Where IDA has them: VA 0x1e4c90, 0x1e3b0a (not even 4-aligned), 0x1e4c60. */
    chk("header_kek_source", memcmp(s.header_kek_source, ro + 0x1e4c90 - 0x1df000, 16) == 0);
    chk("header_key_source (unaligned)", memcmp(s.header_key_source, ro + 0x1e3b0a - 0x1df000, 32) == 0);
    chk("key_area_key_application_source", memcmp(s.key_area_key_application_source, ro + 0x1e4c60 - 0x1df000, 16) == 0);
    chk("no matches elsewhere", gc_find_key_sources(ro + 0x6000, 0x4000, gc_sha256, &s) == 0);
    free(ro);
}

int main(void)
{
    test_xts();
    test_card();
    test_key_sources();
    printf(fails ? "test_nca: %d FAILED\n" : "test_nca: all passed\n", fails);
    return fails ? 1 : 0;
}
