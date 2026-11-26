/* xci_view.c - see xci_view.h. */
#include "xci_view.h"

#include <stdio.h>
#include <string.h>

#include "hh_window.h"

static bool is_xci(uint32_t rc)
{
    return (rc & 0x1FFu) == XCI_RESULT_MODULE;
}

const char *xci_error_name(uint32_t rc)
{
    if (!is_xci(rc))
        return NULL;
    switch ((rc >> 9) & 0x1FFFu) {
    case XciError_InvalidIndex:  return "InvalidIndex";
    case XciError_InvalidPath:   return "InvalidPath";
    case XciError_OpenFailed:    return "OpenFailed";
    case XciError_Busy:          return "Busy";
    case XciError_GameCardInUse: return "GameCardInUse";
    case XciError_ListFailed:    return "ListFailed";
    case XciError_NotAnImage:    return "NotAnImage";
    default:                     return NULL;
    }
}

const char *xci_error_hint(uint32_t rc)
{
    if (!is_xci(rc))
        return NULL;
    switch ((rc >> 9) & 0x1FFFu) {
    case XciError_InvalidIndex:  return "no image at that position, refresh";
    case XciError_InvalidPath:   return "not an image name or path";
    case XciError_OpenFailed:    return "file missing or unreadable";
    case XciError_Busy:          return "a swap is still in progress";
    case XciError_GameCardInUse: return "close the game card title first";
    case XciError_ListFailed:    return "library directory unreadable";
    case XciError_NotAnImage:    return "file has no XCI card header";
    default:                     return NULL;
    }
}

void xci_error_describe(uint32_t rc, char *out, size_t n)
{
    const char *name = xci_error_name(rc);
    if (name)
        snprintf(out, n, "%s: %s", name, xci_error_hint(rc));
    else
        snprintf(out, n, "error 0x%x", (unsigned)rc);
}

const char *xci_stage_name(uint32_t stage)
{
    switch (stage) {
    case 0:                          return "hook not mapped yet";
    case HH_STAGE_MAPPED:            return "window mapped";
    case HH_STAGE_EMPTY:             return "no image";
    case HH_STAGE_ATTACH_FAILED:     return "image rejected";
    case HH_STAGE_ARMED:             return "armed";
    case HH_STAGE_WAKE_NO_FS:        return "FS build mismatch";
    case HH_STAGE_WAKE_NO_DETECTOR:  return "nn.gc not started";
    case HH_STAGE_WAKE_NO_EVENT:     return "detector not running";
    case HH_STAGE_WAKE_SENT:         return "inserted";
    case HH_STAGE_SWAP_REMOVING:     return "swap: removing";
    case HH_STAGE_SWAP_DETACHED:     return "swap: removed";
    case HH_STAGE_SWAP_INSERTING:    return "swap: inserting";
    case HH_STAGE_SWAP_INSERTED:     return "inserted (swapped)";
    case HH_STAGE_SWAP_EMPTY:        return "swap: no image";
    case HH_STAGE_SWAP_TIMEOUT:      return "swap: sysmodule timeout";
    case HH_STAGE_SWAP_FAILED:       return "swap: image rejected";
    default:                         return "?";
    }
}

xci_card_t xci_card_state(const XciStatus *st)
{
    switch (st->stage) {
    case 0:
    case HH_STAGE_MAPPED:
        return XCI_CARD_UNKNOWN;
    case HH_STAGE_EMPTY:
    case HH_STAGE_SWAP_EMPTY:
        return XCI_CARD_NONE;
    case HH_STAGE_ATTACH_FAILED:
    case HH_STAGE_SWAP_TIMEOUT:
    case HH_STAGE_SWAP_FAILED:
        return XCI_CARD_FAILED;
    case HH_STAGE_SWAP_REMOVING:
    case HH_STAGE_SWAP_DETACHED:
        return XCI_CARD_REMOVING;
    case HH_STAGE_SWAP_INSERTING:
        return XCI_CARD_INSERTING;
    default:
        /* Inserted: mounted once FS has read it (GC_STATUS_MOUNTED). */
        return st->mount_code == 256 ? XCI_CARD_MOUNTED : XCI_CARD_INSERTING;
    }
}

const char *xci_card_text(xci_card_t card)
{
    switch (card) {
    case XCI_CARD_NONE:      return "no card";
    case XCI_CARD_REMOVING:  return "removing";
    case XCI_CARD_INSERTING: return "inserting";
    case XCI_CARD_MOUNTED:   return "mounted";
    case XCI_CARD_FAILED:    return "failed";
    default:                 return "starting";
    }
}

void xci_format_size(uint64_t size, char *out, size_t n)
{
    if (size >= (1ull << 30))
        snprintf(out, n, "%.2f GiB", (double)size / (double)(1ull << 30));
    else if (size >= (1ull << 20))
        snprintf(out, n, "%.1f MiB", (double)size / (double)(1ull << 20));
    else
        snprintf(out, n, "%u KiB", (unsigned)((size + 1023) >> 10));
}

void xci_entry_label(const XciImageEntry *e, char *out, size_t n)
{
    snprintf(out, n, "%s%.*s", (e->flags & XCI_IMAGE_FLAG_CURRENT) ? "* " : "",
             (int)XCI_NAME_MAX, e->name);
}

void xci_entry_value(const XciImageEntry *e, char *out, size_t n)
{
    char size[24];
    xci_format_size(e->size, size, sizeof(size));
    snprintf(out, n, "%u part%s  %s", (unsigned)e->parts, e->parts == 1 ? "" : "s", size);
}

int xci_current_index(const XciImageEntry *entries, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
        if (entries[i].flags & XCI_IMAGE_FLAG_CURRENT)
            return (int)i;
    return -1;
}

/* Length of an entry name; names are NUL-padded to XCI_NAME_MAX. */
static size_t name_len(const XciImageEntry *e)
{
    size_t len = 0;
    while (len < XCI_NAME_MAX && e->name[len])
        len++;
    return len;
}

void xci_entry_title(const XciImageEntry *e, char *out, size_t n)
{
    size_t len = name_len(e);
    if (len > 4 && memcmp(e->name + len - 4, ".xci", 4) == 0)
        len -= 4;
    snprintf(out, n, "%.*s", (int)len, e->name);
}

void xci_entry_location(const char *library, const XciImageEntry *e, char *out, size_t n)
{
    const int len = (int)name_len(e);
    if (len > 4 && memcmp(e->name + len - 4, ".xci", 4) == 0)
        snprintf(out, n, "%s%.*s", library, len, e->name);
    else if (e->parts > 1)
        snprintf(out, n, "%s%.*s.xc0 + .xc1", library, len, e->name);
    else
        snprintf(out, n, "%s%.*s.xc0", library, len, e->name);
}

void xci_entry_subtitle(const char *library, const XciImageEntry *e, char *out, size_t n)
{
    char where[XCI_PATH_MAX + XCI_NAME_MAX + 16], size[24];
    xci_entry_location(library, e, where, sizeof(where));
    xci_format_size(e->size, size, sizeof(size));
    snprintf(out, n, "%s, %s", where, size);
}

float xci_carousel_first(uint32_t count, uint32_t selected, uint32_t visible, float first)
{
    if (visible == 0 || count <= visible)
        return 0.0f;
    int target = (int)(first + 0.5f);
    if ((int)selected < target)
        target = (int)selected;
    else if ((int)selected > target + (int)visible - 1)
        target = (int)selected - (int)visible + 1;
    const int last = (int)(count - visible);
    if (target > last)
        target = last;
    if (target < 0)
        target = 0;
    return (float)target;
}

void xci_sel_init(xci_sel_t *s)
{
    memset(s, 0, sizeof(*s));
}

bool xci_sel_can_start(const xci_sel_t *s)
{
    return s->phase != XCI_SEL_RUNNING && s->phase != XCI_SEL_SWAPPING;
}

void xci_sel_start(xci_sel_t *s, const char *name)
{
    s->phase = XCI_SEL_RUNNING;
    s->result = 0;
    snprintf(s->name, sizeof(s->name), "%s", name);
    snprintf(s->message, sizeof(s->message), "selecting %s", s->name);
}

void xci_sel_finish(xci_sel_t *s, uint32_t result, const XciStatus *st)
{
    s->result = result;
    if (result != 0) {
        char why[128];
        xci_error_describe(result, why, sizeof(why));
        snprintf(s->message, sizeof(s->message), "%s", why);
        s->phase = XCI_SEL_FAILED;
        return;
    }
    s->gen = st->swap_req;
    s->phase = XCI_SEL_SWAPPING;
    xci_sel_poll(s, st);
}

void xci_sel_poll(xci_sel_t *s, const XciStatus *st)
{
    if (s->phase != XCI_SEL_SWAPPING)
        return;
    xci_card_t card = xci_card_state(st);
    bool files_switched = (int32_t)(st->swap_done - s->gen) >= 0;
    bool hook_resting = st->stage != HH_STAGE_SWAP_REMOVING && st->stage != HH_STAGE_SWAP_DETACHED &&
                        st->stage != HH_STAGE_SWAP_INSERTING && st->stage != HH_STAGE_SWAP_TIMEOUT;
    if (files_switched && hook_resting) {
        if (card == XCI_CARD_FAILED || card == XCI_CARD_NONE) {
            snprintf(s->message, sizeof(s->message), "swap to %s failed: %s", s->name,
                     xci_stage_name(st->stage));
            s->phase = XCI_SEL_FAILED;
        } else {
            snprintf(s->message, sizeof(s->message), "now: %s", s->name);
            s->phase = XCI_SEL_DONE;
        }
        return;
    }
    /* Accepted but the hook has not started yet: the old card is about to go. */
    if (hook_resting)
        card = XCI_CARD_REMOVING;
    if (st->stage == HH_STAGE_SWAP_TIMEOUT)
        snprintf(s->message, sizeof(s->message), "swapping to %s: waiting for the sysmodule", s->name);
    else
        snprintf(s->message, sizeof(s->message), "swapping to %s: %s", s->name, xci_card_text(card));
}
