#include "lotus3.h"
#include "crypto.h"
#include "gc_cert.h"

enum { ENC_NONE = 0, ENC_CBC = 1, ENC_CTR = 2 };

static size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }

static bool is_cbc_op(uint8_t op) { return op >= 0x06 && op <= 0x09; }

static void derive_session(l3_t *l3)
{
    uint8_t msg[64], mac[32];
    memcpy(msg + 0, l3->asic_rand, 32);
    memcpy(msg + 32, l3->host_rand, 32);
    gc_hmac_sha256(&l3->lafw_type, 1, msg, sizeof(msg), mac);
    memcpy(l3->key, mac, 16);
    memcpy(l3->iv, mac + 16, 16);
    l3->key_ready = true;
}

void l3_set_cert(l3_t *l3, const uint8_t *cert, size_t len)
{
    l3->cert_len = min_sz(len, sizeof(l3->cert));
    memcpy(l3->cert, cert, l3->cert_len);
}

void l3_set_raw(l3_t *l3, bool raw)
{
    l3->raw = raw;
}

void l3_init(l3_t *l3, gc_random_fn rng, void *rng_ctx)
{
    memset(l3, 0, sizeof(*l3));
    l3->rng = rng;
    l3->rng_ctx = rng_ctx;
    l3->state = L3_STATE_IDLE;
    l3->skip_initdata_check = true; /* requires FS-side patch (0x187A1C on 23.5.0) */
    memset(l3->host_rand, 0x11, 32); /* FS RNG hook output */
    static const uint32_t regs[L3_NREGS] = {
        0x00000000, 0x00A10011, 0x00001388, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x0000000F, 0x00000000,
    };
    memcpy(l3->regs, regs, sizeof(l3->regs));

    if (rng)
        rng(rng_ctx, l3->asic_rand, sizeof(l3->asic_rand));
    else
        memset(l3->asic_rand, 0x22, sizeof(l3->asic_rand));

    /* InitialData: challenge data in 0x10..0x3B, everything else empty. */
    memset(l3->initial_data, 0, sizeof(l3->initial_data));
    if (rng)
        rng(rng_ctx, l3->initial_data + 0x10, 0x2C);
    else
        memset(l3->initial_data + 0x10, 0x33, 0x2C);

    /* CardUid: MakerId 0, 13 bytes unique data, 0x11 reserved. */
    l3->card_uid[0] = 0x00;
    if (rng)
        rng(rng_ctx, l3->card_uid + 3, 13);
    memset(l3->card_uid + 0x11, 0xFF, 0x0B);

    /* The genuine CN=LOTUS3 certificate, as the ASIC serves it in op 0x02.
     * FS verifies it with its baked-in CA key; no signature patch is needed.
     * A caller may substitute another block with l3_set_cert(). */
    gc_cert_block(l3->cert);
    l3->cert_len = GC_CERT_BLOCK_SIZE;
}

int l3_attach(l3_t *l3, gc_image_t *img)
{
    if (!img) {
        l3->state = L3_STATE_FAILED;
        return -1;
    }
    l3->page_base = 0;
    if (gc_image_read(img, 0, l3->xci_header, sizeof(l3->xci_header)) ||
        memcmp(l3->xci_header + 0x100, "HEAD", 4) != 0) {
        /* Legacy full-card synthetic image keeps a 0x1000 CardKeyArea. */
        l3->page_base = 0x1000;
        if (gc_image_read(img, l3->page_base, l3->xci_header, sizeof(l3->xci_header)) ||
            memcmp(l3->xci_header + 0x100, "HEAD", 4) != 0) {
            l3->state = L3_STATE_FAILED;
            return -1;
        }
    }
    /* Card IDs. ID1: maker code (Macronix), the header's capacity code
     * (0x10D), then zeros. ID2/ID3 are per-card; FS only compares them with
     * the copies in the CardHeader and the CardKeyArea. */
    l3->card_id1[0] = 0xC2;
    l3->card_id1[1] = l3->xci_header[0x10D];
    l3->card_id1[2] = 0;
    l3->card_id1[3] = 0;
    memcpy(l3->card_id2, l3->card_uid + 3, sizeof(l3->card_id2));
    memcpy(l3->card_id3, l3->card_uid + 7, sizeof(l3->card_id3));

    /* Lotus3 CardHeader: CupVersion, CardId1, then the XCI CardHeader
     * verbatim. 0x100..0x1FF is inside Nintendo's signature, so it is copied
     * byte-for-byte and never rewritten. The caller decrypts CardInfo and
     * appends the MAC per read (gc_asic_authenticate). */
    memset(l3->card_header, 0, sizeof(l3->card_header));
    gc_wr32(l3->card_header + 0, 0);
    memcpy(l3->card_header + 4, l3->card_id1, sizeof(l3->card_id1));
    memcpy(l3->card_header + 8, l3->xci_header + 0x100, 0x100);

    /* The card certificate sits at image 0x7000. A blanked one (all 0xFF or
     * all zero) is replaced by a stand-in with the fields FS compares: magic,
     * KEK index (must equal header 0x10C & 0xF) and DeviceId. */
    bool blank = gc_image_read(img, (uint64_t)l3->page_base + 0x7000,
                               l3->card_cert, sizeof(l3->card_cert)) != 0;
    if (!blank) {
        bool ff = true, zero = true;
        for (size_t i = 0; i < sizeof(l3->card_cert); i++) {
            ff = ff && l3->card_cert[i] == 0xFF;
            zero = zero && l3->card_cert[i] == 0x00;
        }
        blank = ff || zero;
    }
    l3->card_cert_genuine = !blank;
    if (blank) {
        memset(l3->card_cert, 0xFF, 0x100); /* no signature */
        memset(l3->card_cert + 0x100, 0, 0x100);
        memcpy(l3->card_cert + 0x100, "CERT", 4);
        l3->card_cert[0x108] = l3->xci_header[0x10C] & 0x0F;
        memcpy(l3->card_cert + 0x110, l3->card_uid, 0x10); /* DeviceId */
    }

    l3->img = img;
    l3->state = L3_STATE_MOUNTED;
    return 0;
}

static void crypt_buf(l3_t *l3, uint8_t *buf, size_t len, bool decrypt)
{
    if (len == 0 || l3->enc_mode == ENC_NONE)
        return;
    if (l3->enc_mode == ENC_CBC) {
        if (decrypt)
            gc_aes128_cbc_decrypt(l3->key, l3->iv, buf, buf, len);
        else
            gc_aes128_cbc_encrypt(l3->key, l3->iv, buf, buf, len);
    } else if (l3->enc_mode == ENC_CTR) {
        uint8_t cv[16];
        memcpy(cv, l3->cv, 16);
        gc_aes128_ctr(l3->key, cv, buf, buf, len);
    }
}

/* CardKeyArea as FS 23.5.0 reads it (sub_187930, frame of 0x800):
 *   0x008 CardId1, 0x00C CardId2   compared with CardHeader / ID2 read
 *   0x1E0 MAC over 0x200..0x7FF    appended by gc_asic_authenticate
 *   0x200 card certificate         0x308 KEK index, 0x310 DeviceId
 *   0x600 InitialData              zero from 0x63C on */
static void build_key_area(l3_t *l3, uint8_t *p)
{
    memset(p, 0, 0x800);
    gc_wr32(p + 0x000, 1);           /* SecurityLevel */
    gc_wr32(p + 0x004, 0);           /* Lotus3Status */
    memcpy(p + 0x008, l3->card_id1, sizeof(l3->card_id1));
    memcpy(p + 0x00C, l3->card_id2, sizeof(l3->card_id2));
    memcpy(p + 0x010, l3->card_uid, sizeof(l3->card_uid));
    memcpy(p + 0x200, l3->card_cert, sizeof(l3->card_cert));
    memcpy(p + 0x600, l3->initial_data, sizeof(l3->initial_data));
}

/* SendCardCommand with a one-word reply (header byte 1 == 1). FS 23.5.0
 * picks the command byte by link mode 0..3 (sub_18B090 / sub_18B220 /
 * sub_18B3C0) and takes the first u32 of the 0x200 frame. */
static const uint8_t *card_id_for(const l3_t *l3, uint8_t kind, uint8_t cmd)
{
    if (kind != 1)
        return NULL;
    switch (cmd) {
    case 0x56: case 0x67: case 0x10: return l3->card_id1;
    case 0x28: case 0xC4: case 0x11: return l3->card_id2;
    case 0xA5: case 0x30: case 0x12: return l3->card_id3;
    default: return NULL;
    }
}

int l3_cmd60(l3_t *l3, const uint8_t op[GC_OP_SIZE])
{
    if (!op)
        return -1;
    l3->op = op[0];
    memcpy(l3->opdata, op + 1, sizeof(l3->opdata));
    memcpy(l3->cv, op + 0x20, sizeof(l3->cv));
    l3->pending_dir = 0;
    l3->pending_len = 0;
    l3->pending_pos = 0;
    l3->scc_direct = false;
    l3->status = 0;
    memset(l3->stage, 0, sizeof(l3->stage));

    if (l3->raw)
        l3->enc_mode = ENC_NONE; /* hook sits above FS's session crypto */
    else if (l3->secure)
        l3->enc_mode = ENC_CTR;
    else if (is_cbc_op(l3->op))
        l3->enc_mode = ENC_CBC;
    else
        l3->enc_mode = ENC_NONE;

    switch (l3->op) {
    case 0x01: /* SendFirmware */
        l3->pending_dir = 2;
        l3->pending_len = 0x7800;
        l3->fw_pos = 0;
        l3->enc_mode = ENC_NONE;
        break;
    case 0x02: /* ReceiveCertificate */
        l3->pending_dir = 1;
        l3->pending_len = 0x400;
        memcpy(l3->stage, l3->cert, min_sz(l3->cert_len, 0x400));
        break;
    case 0x03: /* SendSocCertificate */
        l3->pending_dir = 2;
        l3->pending_len = 0x400;
        break;
    case 0x04: { /* ReceiveRandomValue: RSA-OAEP(asic_rand) to SoC modulus */
        l3->pending_dir = 1;
        l3->pending_len = 0x100;
        if (!l3->have_soc) {
            l3->status = 1;
            memset(l3->stage, 0xFF, 0x100);
            break;
        }
        uint8_t seed[32];
        if (l3->rng)
            l3->rng(l3->rng_ctx, seed, sizeof(seed));
        else
            memset(seed, 0x44, sizeof(seed));
        if (gc_rsa2048_oaep_sha256_encrypt(l3->soc_mod, l3->asic_rand,
                                           sizeof(l3->asic_rand), seed, l3->stage)) {
            l3->status = 1;
            memset(l3->stage, 0xFF, 0x100);
        }
        break;
    }
    case 0x05: /* SendRandomValue */
        l3->pending_dir = 2;
        l3->pending_len = 0x100;
        break;
    /* FS 23.5.0 runs the challenge exchange as raw 32-byte values (sub_1899B0):
     * op 6 returns the device random, op 7 takes SHA-256(device random), op 8
     * takes the host challenge and op 9 must answer SHA-256(host challenge),
     * which FS memcmps against its own hash (2002-2655 on mismatch). Frames
     * here are plaintext; FS decrypts device -> host frames with its session
     * key after the executor, so the caller seals them (gc_link_seal). The
     * legacy CBC path keeps the 0x200-byte frames. */
    case 0x06: /* ReceiveDeviceChallenge */
        if (!l3->key_ready)
            derive_session(l3);
        l3->pending_dir = 1;
        l3->pending_len = l3->raw ? 0x20 : 0x200;
        memset(l3->stage, 0xFF, l3->raw ? 0x20 : 0x200);
        memcpy(l3->stage, l3->asic_rand, sizeof(l3->asic_rand));
        break;
    case 0x07: /* RespondDeviceChallenge */
        if (!l3->key_ready)
            derive_session(l3);
        l3->pending_dir = 2;
        l3->pending_len = l3->raw ? 0x20 : 0x200;
        break;
    case 0x08: /* SendHostChallenge */
        if (!l3->key_ready)
            derive_session(l3);
        l3->pending_dir = 2;
        l3->pending_len = l3->raw ? 0x20 : 0x200;
        break;
    case 0x09: /* ReceiveChallengeResponse */
        if (!l3->key_ready)
            derive_session(l3);
        l3->pending_dir = 1;
        l3->pending_len = l3->raw ? 0x20 : 0x200;
        if (l3->raw)
            gc_sha256(l3->host_challenge, sizeof(l3->host_challenge), l3->stage);
        else
            memcpy(l3->stage, l3->host_challenge, sizeof(l3->host_challenge));
        break;
    case 0x0A: /* ChangeModeToSecure */
        if (!l3->key_ready)
            derive_session(l3);
        l3->secure = true;
        break;
    case 0x0B: /* WriteRegister: register byte offset in header +4 */
        /* FS 23.5.0 sends the 4-byte value as its logical length
         * (sub_18AEB0: mode 1, buffer &value, len 4). */
        l3->pending_dir = 2;
        l3->pending_len = l3->raw ? 4 : 0x200;
        break;
    case 0x0C: /* ReadRegister: the 12-word register file */
        l3->pending_dir = 1;
        l3->pending_len = 0x200;
        for (int i = 0; i < L3_NREGS; i++)
            gc_wr32(l3->stage + 4 * i, l3->regs[i]);
        break;
    case 0x0D: /* ChangeGcModeToDebug */
        l3->pending_dir = 1;
        l3->pending_len = 0x200;
        break;
    case 0x0E: /* GetCardHeader */
        l3->pending_dir = 1;
        l3->pending_len = 0x200;
        memcpy(l3->stage, l3->card_header, sizeof(l3->card_header));
        break;
    case 0x0F: /* ChangeGcModeToSecure: CardKeyArea */
        l3->pending_dir = 1;
        l3->pending_len = 0x800;
        build_key_area(l3, l3->stage);
        break;
    case 0x10: { /* SendCardCommand */
        const uint8_t *id = card_id_for(l3, l3->opdata[0], l3->opdata[7]);
        if (id) {
            l3->pending_dir = 1;
            l3->pending_len = GC_PAGE_SIZE;
            memcpy(l3->stage, id, 4);
            break;
        }
        if (l3->opdata[0] == 3) { /* multi-page wrapper: count LE, page BE */
            l3->scc_count = gc_rd32(l3->opdata + 3);
            l3->scc_page = gc_rd32be(l3->opdata + 8);
        } else { /* single-page wrapper */
            l3->scc_page = gc_rd32(l3->opdata + 3);
            l3->scc_count = 1;
        }
        l3->scc_dir = l3->opdata[1];
        l3->scc_cmd = l3->opdata[7];
        if (l3->scc_count == 0)
            l3->scc_count = 1;
        if (l3->raw && l3->scc_dir == 0) {
            /* FS 23.5.0 reads whole partition headers in one op (0x8E pages
             * seen), straight into its buffer: serve the pages from the
             * image in the data phase instead of staging them. */
            if (l3->scc_count > L3_MAX_DIRECT_PAGES)
                l3->scc_count = L3_MAX_DIRECT_PAGES;
            uint64_t off = (uint64_t)l3->page_base + (uint64_t)l3->scc_page * GC_PAGE_SIZE;
            uint32_t len = l3->scc_count * GC_PAGE_SIZE;
            l3->pending_dir = 1;
            l3->pending_len = len;
            l3->scc_direct = true;
            if (l3->state != L3_STATE_MOUNTED || !l3->img ||
                len > l3->img->size || off > l3->img->size - len)
                l3->status = 1;
            break;
        }
        if (l3->scc_count > 8)
            l3->scc_count = 8;
        uint32_t len = l3->scc_count * GC_PAGE_SIZE;
        if (l3->scc_dir == 0) { /* read */
            l3->pending_dir = 1;
            l3->pending_len = len;
            if (l3->state != L3_STATE_MOUNTED || !l3->img ||
                gc_image_read(l3->img, (uint64_t)l3->page_base +
                              (uint64_t)l3->scc_page * GC_PAGE_SIZE,
                              l3->stage, len)) {
                memset(l3->stage, 0xFF, len);
                l3->status = 1;
            } else {
                l3->pages_served += l3->scc_count;
            }
        } else {
            l3->pending_dir = 2;
            l3->pending_len = len;
        }
        break;
    }
    case 0x11: /* EnableCardBus */
        break;
    case 0x12: /* ExchangeRandomValuesInSecureMode */
        l3->pending_dir = 1;
        l3->pending_len = 0x200;
        memcpy(l3->stage, l3->asic_rand, sizeof(l3->asic_rand));
        break;
    case 0x13: /* ReadRmaInformation */
        l3->pending_dir = 1;
        l3->pending_len = 0x200;
        break;
    case 0x14: /* ChallengeCardExistence (9.0.0+) */
        l3->pending_dir = 1;
        l3->pending_len = 0x200;
        memcpy(l3->stage, l3->card_uid, sizeof(l3->card_uid));
        break;
    default:
        break;
    }

    if (l3->pending_dir == 1 && l3->enc_mode != ENC_NONE) {
        if (!l3->key_ready) {
            l3->status = 1;
        } else {
            crypt_buf(l3, l3->stage, l3->pending_len, false);
        }
    }
    return l3->status ? -1 : 0;
}

int l3_data_read(l3_t *l3, void *buf, size_t len)
{
    if (!l3 || !buf || l3->pending_dir != 1)
        return -1;
    if (len > l3->pending_len - l3->pending_pos)
        return -1;
    if (l3->scc_direct) {
        uint64_t off = (uint64_t)l3->page_base + (uint64_t)l3->scc_page * GC_PAGE_SIZE +
                       l3->pending_pos;
        if (l3->status || gc_image_read(l3->img, off, buf, len))
            return -1;
        l3->pages_served += len / GC_PAGE_SIZE;
    } else {
        memcpy(buf, l3->stage + l3->pending_pos, len);
    }
    l3->pending_pos += (uint32_t)len;
    return 0;
}

int l3_data_write(l3_t *l3, const void *buf, size_t len)
{
    if (!l3 || !buf || l3->pending_dir != 2)
        return -1;
    if (len > l3->pending_len - l3->pending_pos)
        return -1;
    const uint8_t *p = (const uint8_t *)buf;

    if (l3->op == 0x01) { /* streamed LAFW; only the type byte matters */
        for (size_t i = 0; i < len; i++) {
            uint32_t pos = l3->fw_pos + (uint32_t)i;
            if (pos == 0x110)
                l3->lafw_type = p[i];
        }
        l3->fw_pos += (uint32_t)len;
        l3->pending_pos += (uint32_t)len;
        return 0;
    }

    memcpy(l3->stage + l3->pending_pos, p, len);
    l3->pending_pos += (uint32_t)len;
    return 0;
}

int l3_cmd61(l3_t *l3, uint32_t *status)
{
    if (!l3)
        return -1;

    if (l3->pending_dir == 2 && l3->op != 0x01) {
        if (l3->pending_pos != l3->pending_len) {
            l3->status = 1;
        } else if (l3->enc_mode != ENC_NONE) {
            if (!l3->key_ready)
                l3->status = 1;
            else
                crypt_buf(l3, l3->stage, l3->pending_len, true);
        }
        if (!l3->status) {
            switch (l3->op) {
            case 0x03: /* SoC certificate: modulus at +0x130 */
                memcpy(l3->soc_mod, l3->stage + 0x130, sizeof(l3->soc_mod));
                l3->have_soc = true;
                break;
            case 0x08: /* host challenge, now plaintext */
                memcpy(l3->host_challenge, l3->stage, sizeof(l3->host_challenge));
                l3->have_host_challenge = true;
                break;
            case 0x0B: { /* WriteRegister */
                uint32_t reg = gc_rd32(l3->opdata + 3) / 4;
                if (reg < L3_NREGS)
                    l3->regs[reg] = gc_rd32(l3->stage);
                break;
            }
            default:
                break;
            }
        }
    }
    if (l3->op == 0x01 && l3->pending_pos != l3->pending_len)
        l3->status = 1;

    if (status)
        *status = (uint32_t)l3->status;
    int rc = l3->status ? -1 : 0;
    l3->pending_dir = 0;
    return rc;
}
