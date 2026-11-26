#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hh.h"

static int fails;

static void chk(const char *what, int ok)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
        fails++;
}

static void test_table(const hh_sites_t *s, const char *label, size_t sz)
{
    printf("-- %s\n", label);
    if (s->executor + 16 > sz || s->presence + 16 > sz || s->initdata_call + 4 > sz) {
        printf("FAIL sites outside image\n");
        fails++;
        return;
    }
    uint8_t *img = (uint8_t *)malloc(sz);
    memset(img, 0xAA, sz);

    hh_hooks_t hooks = { (const void *)0x1234567890ULL, (const void *)0xABCDEF00ULL };
    chk("install", hh_install(img, s, &hooks) == 0);

    const uint8_t *e = img + s->executor;
    chk("executor ldr x16", memcmp(e, "\x50\x00\x00\x58", 4) == 0);
    chk("executor br x16", memcmp(e + 4, "\x00\x02\x1F\xD6", 4) == 0);
    uint64_t t;
    memcpy(&t, e + 8, 8);
    chk("executor target", t == 0x1234567890ULL);

    const uint8_t *p = img + s->presence;
    chk("presence ldr x16", memcmp(p, "\x50\x00\x00\x58", 4) == 0);
    memcpy(&t, p + 8, 8);
    chk("presence target", t == 0xABCDEF00ULL);

    const uint8_t *c = img + s->initdata_call;
    chk("initdata MOV W0,#0", memcmp(c, "\x00\x00\x80\x52", 4) == 0);
    if (s->cert_call) {
        const uint8_t *k = img + s->cert_call;
        chk("card cert MOV W0,#0", memcmp(k, "\x00\x00\x80\x52", 4) == 0);
        chk("byte after card cert untouched", img[s->cert_call + 4] == 0xAA);
    }

    chk("byte before executor untouched", img[s->executor - 1] == 0xAA);
    chk("byte after executor untouched", img[s->executor + 16] == 0xAA);

    hh_sites_t bad = *s;
    bad.presence = bad.executor + 8;
    chk("overlap rejected", hh_install(img, &bad, &hooks) == -1);
    chk("null target rejected", hh_install(img, s, &(hh_hooks_t){0}) == -1);

    free(img);
}

/* The 23.5.0 sites against the FS image itself: the instruction each patch
 * replaces must be the documented call. */
static int fs_word(FILE *f, uint64_t va, uint32_t *out)
{
    uint8_t eh[64];
    if (fseek(f, 0, SEEK_SET) || fread(eh, 1, sizeof(eh), f) != sizeof(eh))
        return -1;
    uint64_t phoff;
    uint16_t phentsize, phnum;
    memcpy(&phoff, eh + 0x20, 8);
    memcpy(&phentsize, eh + 0x36, 2);
    memcpy(&phnum, eh + 0x38, 2);
    for (uint16_t i = 0; i < phnum; i++) {
        uint8_t ph[56];
        if (fseek(f, (long)(phoff + (uint64_t)i * phentsize), SEEK_SET) ||
            fread(ph, 1, sizeof(ph), f) != sizeof(ph))
            return -1;
        uint32_t type;
        uint64_t off, vaddr, filesz;
        memcpy(&type, ph, 4);
        memcpy(&off, ph + 8, 8);
        memcpy(&vaddr, ph + 16, 8);
        memcpy(&filesz, ph + 32, 8);
        if (type == 1 && va >= vaddr && va + 4 <= vaddr + filesz) {
            if (fseek(f, (long)(off + va - vaddr), SEEK_SET) || fread(out, 1, 4, f) != 4)
                return -1;
            return 0;
        }
    }
    return -1;
}

static void test_fs_23_5_0_words(void)
{
    printf("-- 23.5.0 FS image\n");
    FILE *f = fopen("fw_elf_kip_23.5.0/0100000000000000_FS.elf", "rb");
    if (!f) {
        printf("skip (FS image not present)\n");
        return;
    }
    uint32_t w = 0;
    chk("0x187A1C is BL sub_191390",
        fs_word(f, HH_FS_23_5_0.initdata_call, &w) == 0 && w == 0x9400265Du);
    chk("0x187B30 is BL sub_18FDC0",
        fs_word(f, HH_FS_23_5_0.cert_call, &w) == 0 && w == 0x940020A4u);
    chk("0x187B34 is CBZ W0 (patch result consumed)",
        fs_word(f, HH_FS_23_5_0.cert_call + 4, &w) == 0 && w == 0x34000340u);
    fclose(f);
}

int main(void)
{
    test_table(&HH_FS_22_5_0, "22.5.0", 0x1E0000);
    test_table(&HH_FS_23_5_0, "23.5.0", 0x1E0000);
    test_fs_23_5_0_words();
    if (fails) {
        printf("\n%d FAILURE(S)\n", fails);
        return 1;
    }
    printf("\nall hook-host layout checks pass\n");
    return 0;
}
