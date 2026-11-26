#include "asic.h"
#include "crypto.h"

void gc_asic_init(gc_asic_t *a, gc_random_fn rng, void *rng_ctx)
{
    l3_init(&a->l3, rng, rng_ctx);
    l3_set_raw(&a->l3, true);
}

int gc_asic_attach(gc_asic_t *a, gc_image_t *img)
{
    return l3_attach(&a->l3, img);
}

void gc_asic_detach(gc_asic_t *a)
{
    a->l3.img = NULL;
    a->l3.state = L3_STATE_IDLE;
}

void gc_asic_set_cert(gc_asic_t *a, const uint8_t *cert, size_t len)
{
    l3_set_cert(&a->l3, cert, len);
}

int gc_asic_exec(gc_asic_t *a, uint32_t *status, void *data, size_t len,
                 const uint8_t hdr[GC_OP_SIZE])
{
    if (!a || !hdr)
        return -1;
    l3_t *l3 = &a->l3;
    if (status)
        *status = 1;

    if (l3_cmd60(l3, hdr)) {
        if (status)
            *status = (uint32_t)l3->status;
        return -1;
    }

    if (l3->pending_dir == 1) { /* device -> host */
        if (!data || len < l3->pending_len) {
            l3->status = 1;
            goto done;
        }
        if (l3_data_read(l3, data, l3->pending_len)) {
            l3->status = 1;
            goto done;
        }
    } else if (l3->pending_dir == 2) { /* host -> device */
        if (!data || len < l3->pending_len) {
            l3->status = 1;
            goto done;
        }
        if (l3_data_write(l3, data, l3->pending_len)) {
            l3->status = 1;
            goto done;
        }
    }

done:
    {
        uint32_t st = 0;
        int rc = l3_cmd61(l3, &st);
        if (status)
            *status = st;
        return rc;
    }
}

/* sub_1902C0: HMAC-SHA256(key, SHA-256(data) || reply counter || salt). */
static void card_mac(const gc_card_secrets_t *s, const uint8_t *data, size_t len,
                     uint8_t out[32])
{
    uint8_t msg[64];
    gc_sha256(data, len, msg);
    memcpy(msg + 32, s->mac_ctr, 16);
    memcpy(msg + 48, s->mac_salt, 16);
    gc_hmac_sha256(s->mac_key, 32, msg, sizeof(msg), out);
}

void gc_asic_authenticate(gc_asic_t *a, uint8_t *frame, size_t len,
                          const gc_card_secrets_t *s)
{
    const l3_t *l3 = &a->l3;
    if (l3->status || !frame || !s)
        return;
    if (l3->op == 0x0E && len >= 0x200) {
        /* FS re-encrypts CardInfo (header 0x190, 0x70 bytes) with the header
         * key and IV = byte-reversed header 0x120 (sub_18FE60), then hashes
         * the header against the page read: the card serves it decrypted. */
        uint8_t *hdr = frame + 8;
        if (s->header_key) {
            uint8_t iv[16];
            for (int i = 0; i < 16; i++)
                iv[i] = hdr[0x2F - i];
            gc_aes128_cbc_decrypt(s->header_key, iv, hdr + 0x90, hdr + 0x90, 0x70);
        }
        card_mac(s, frame, 0x1E0, frame + 0x1E0);
    } else if (l3->op == 0x0F && len >= 0x800) {
        card_mac(s, frame + 0x200, 0x600, frame + 0x1E0);
    }
}

void gc_link_seal(gc_link_t mode, const uint8_t key[16], const uint8_t iv[16],
                  uint8_t *buf, size_t buf_len, size_t len)
{
    if (mode == GC_LINK_CTR) {
        /* sub_18B790 decrypts the whole frame as one stream from the counter
         * (its split calls advance the counter block by block). */
        uint8_t ctr[16];
        memcpy(ctr, iv, sizeof(ctr));
        gc_aes128_ctr(key, ctr, buf, buf, buf_len);
    } else if (mode == GC_LINK_CBC) {
        /* Every decrypt call in sub_18B790 restarts from the session IV: the
         * 16-aligned prefix, then a partial tail block on its own. For an
         * aligned length one chain over the frame covers any aligned prefix
         * FS may request. */
        size_t whole = len & ~(size_t)15;
        if (whole == len)
            whole = buf_len;
        gc_aes128_cbc_encrypt(key, iv, buf, buf, whole);
        if (whole < buf_len)
            gc_aes128_cbc_encrypt(key, iv, buf + whole, buf + whole, 16);
    }
}

bool gc_asic_present(gc_asic_t *a, bool gpio_line_low)
{
    /* The executor is only entered for a mounted image in this demo; FS's
     * mount state machine owns the countdown. The physical line wins. */
    if (gpio_line_low)
        return true;
    return a && a->l3.state == L3_STATE_MOUNTED;
}
