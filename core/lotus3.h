/* lotus3.h - software Gamecard ASIC.
 *
 * Speaks the MMC-level vendor protocol FS uses: WriteOperation (CMD60),
 * FinishOperation (CMD61), then a 0x200-page data phase. Crypto model:
 *   - session key/iv = HMAC-SHA256(LAFW type, asic_random || host_random)
 *   - challenge ops 0x06..0x09: AES-128-CBC with the session iv
 *   - after ChangeModeToSecure (0x0A): AES-128-CTR keyed from CvValue
 * The host random is known a priori because FS's RNG hook forces 0x11.
 */
#ifndef GC_LOTUS3_H
#define GC_LOTUS3_H

#include "gc.h"
#include "image.h"

#define L3_NREGS 12 /* ASIC register file, 0x30 bytes in ReadRegister */
#define L3_MAX_DIRECT_PAGES 0x100000u /* 512 MiB per page-read op */

typedef enum {
    L3_STATE_IDLE = 0, /* no image */
    L3_STATE_PENDING,  /* path set, not opened */
    L3_STATE_MOUNTED,  /* pages served */
    L3_STATE_FAILED,   /* pages 0xFF, reads error */
} l3_state_t;

typedef struct {
    gc_random_fn rng;
    void *rng_ctx;
    gc_image_t *img;      /* borrowed; NULL unless mounted */
    uint32_t page_base;   /* 0 for trimmed XCI, 0x1000 for full synthetic */
    l3_state_t state;

    /* session */
    uint8_t asic_rand[32];
    uint8_t host_rand[32]; /* FS side: 0x11 * 32 after the RNG hook */
    uint8_t key[16], iv[16];
    bool key_ready;
    bool secure;
    bool raw;          /* at FS's executor: plaintext frames; reads are sealed
                        * by the caller with gc_link_seal() */
    uint8_t lafw_type;

    /* peer material */
    uint8_t soc_mod[256];
    bool have_soc;
    uint8_t cert[0x400];
    size_t cert_len;
    uint8_t card_uid[0x40];

    /* what we serve */
    uint8_t xci_header[GC_HEADER_SIZE]; /* image bytes 0x1000..0x11FF */
    uint8_t card_header[GC_HEADER_SIZE];/* Lotus3 CardHeader: ?, CardId1, header verbatim */
    /* The card's own certificate (image 0x7000), served in the CardKeyArea at
     * 0x200. Dumpers often blank it to 0xFF; then a stand-in carrying the
     * fields FS compares is served, and FS's RSA check on it must be patched
     * (FS 23.5.0 0x187B30). */
    uint8_t card_cert[GC_PAGE_SIZE];
    bool card_cert_genuine;
    /* SendCardCommand ID reads (ID1/ID2/ID3); ID1 and ID2 recur in the
     * CardHeader and the CardKeyArea, and FS compares them. */
    uint8_t card_id1[4], card_id2[4], card_id3[4];
    uint32_t regs[L3_NREGS]; /* ASIC registers: 0x0B writes, 0x0C reads all */
    uint8_t initial_data[GC_PAGE_SIZE]; /* synthetic; see skip_initdata_check */
    bool skip_initdata_check;           /* FS-side check must be patched out */

    uint8_t host_challenge[32];
    bool have_host_challenge;

    /* operation in flight */
    uint8_t op;
    uint8_t opdata[0x1F];
    uint8_t cv[16];    /* CvValue from op[0x20]: CTR counter for secure ops */
    int pending_dir;   /* 0 none, 1 device->host, 2 host->device */
    uint32_t pending_len;
    uint32_t pending_pos;
    int enc_mode;      /* 0 plain, 1 cbc, 2 ctr */
    uint8_t stage[0x1000];
    uint32_t fw_pos;
    uint32_t scc_page, scc_count;
    uint8_t scc_dir, scc_cmd;
    bool scc_direct;   /* raw page read served from the image in the data phase */

    uint64_t pages_served;
    int status;        /* CMD61 value: 0 ok, nonzero error */
} l3_t;

void l3_init(l3_t *l3, gc_random_fn rng, void *rng_ctx);
/* Opens the image and builds the served card header. Verbatim: the signed
 * 0x100..0x1FF region is never modified, so Nintendo's signature verifies. */
int l3_attach(l3_t *l3, gc_image_t *img);
void l3_set_cert(l3_t *l3, const uint8_t *cert, size_t len);
void l3_set_raw(l3_t *l3, bool raw);

int l3_cmd60(l3_t *l3, const uint8_t op[GC_OP_SIZE]);
int l3_cmd61(l3_t *l3, uint32_t *status);
int l3_data_read(l3_t *l3, void *buf, size_t len);
int l3_data_write(l3_t *l3, const void *buf, size_t len);

#endif /* GC_LOTUS3_H */
