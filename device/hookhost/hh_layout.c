#include "hh.h"
#include <string.h>

const hh_sites_t HH_FS_22_5_0 = {
    .executor = 0x1890B0,
    .presence = 0x189EE0,
    .initdata_call = 0x18471C,
    .bss_base = 0x264000,
};

/* 23.5.0: same shapes, shifted. Executor prologue is byte-identical; the
 * operation-handler cluster moved +0x3300 and the bss base +0x4000. */
const hh_sites_t HH_FS_23_5_0 = {
    .executor = 0x18C3B0,
    .presence = 0x18F280, /* Boolean inserted predicate */
    .initdata_call = 0x187A1C, /* BL sub_191390; CBZ at 0x187A20 */
    .cert_call = 0x187B30,     /* BL sub_18FDC0; CBZ at 0x187B34 */
    .bss_base = 0x268000,
};

void hh_encode_detour(uint8_t out[16], const void *target)
{
    /* ldr x16, [pc, #8] ; br x16 ; .quad target */
    const uint32_t ldr = 0x58000050u; /* LDR X16, literal +8 */
    const uint32_t br = 0xD61F0200u;  /* BR  X16 */
    uint64_t t = (uint64_t)(uintptr_t)target;
    memcpy(out + 0, &ldr, 4);
    memcpy(out + 4, &br, 4);
    memcpy(out + 8, &t, 8);
}

void hh_encode_mov_w0_0(uint8_t out[4])
{
    const uint32_t mov = 0x52800000u; /* MOV W0, #0 */
    memcpy(out, &mov, 4);
}

static bool overlaps(uint32_t a, uint32_t alen, uint32_t b, uint32_t blen)
{
    return a < b + blen && b < a + alen;
}

int hh_install(void *fs, const hh_sites_t *s, const hh_hooks_t *h)
{
    if (!fs || !s || !h || !h->exec_target || !h->presence_target)
        return -1;
    if (overlaps(s->executor, 16, s->presence, 16) ||
        overlaps(s->executor, 16, s->initdata_call, 4) ||
        overlaps(s->presence, 16, s->initdata_call, 4))
        return -1;
    if (s->cert_call &&
        (overlaps(s->executor, 16, s->cert_call, 4) ||
         overlaps(s->presence, 16, s->cert_call, 4) ||
         overlaps(s->initdata_call, 4, s->cert_call, 4)))
        return -1;

    uint8_t *p = (uint8_t *)fs;
    hh_encode_detour(p + s->executor, h->exec_target);
    hh_encode_detour(p + s->presence, h->presence_target);
    hh_encode_mov_w0_0(p + s->initdata_call);
    if (s->cert_call)
        hh_encode_mov_w0_0(p + s->cert_call);
    return 0;
}
