/* Client-side presentation shared by the switcher NRO and the Tesla overlay
 * (device/xci/client/xci_view.c): what is testable without a console. The
 * IPC itself and the on-screen behaviour can only be checked on hardware. */
#include <stdio.h>
#include <string.h>

#include "hh_window.h"
#include "xci_lib.h"
#include "xci_view.h"

static int fails;

static void chk(const char *name, int cond)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        fails++;
}

/* A library directory: names only; the scan never opens files. */
static const struct { const char *name; uint64_t size; } g_dir[] = {
    { "zelda.xci", 0x40000000ull }, { "Mario.xci", 0x20000000ull },
    { "digimon.xc1", 0x9d7d0000ull }, { "digimon.xc0", 0xee6b2800ull },
    { "alone.xc0", 0x1000000ull }, { "orphan.xc1", 0x1000ull }, { "readme.txt", 10 },
    { "._zelda.xci", 4096 }, { "._digimon.xc0", 4096 }, { ".hidden.xc0", 0x1000ull },
};

static int list_dir(void *ctx, const char *dir, void (*add)(void *, const char *, uint64_t), void *cookie)
{
    (void)ctx;
    (void)dir;
    for (size_t i = 0; i < sizeof(g_dir) / sizeof(g_dir[0]); i++)
        add(cookie, g_dir[i].name, g_dir[i].size);
    return 0;
}

static const xci_fs_t g_fs = { NULL, NULL, NULL, list_dir, NULL };

static XciStatus status(uint32_t stage, uint32_t req, uint32_t done, int32_t mount)
{
    XciStatus st;
    memset(&st, 0, sizeof(st));
    st.stage = stage;
    st.swap_req = req;
    st.swap_done = done;
    st.mount_code = mount;
    return st;
}

int main(void)
{
    char buf[200];

    // Error names.
    static const struct { int desc; const char *name; } errs[] = {
        { XciError_InvalidIndex, "InvalidIndex" }, { XciError_InvalidPath, "InvalidPath" },
        { XciError_OpenFailed, "OpenFailed" }, { XciError_Busy, "Busy" },
        { XciError_GameCardInUse, "GameCardInUse" }, { XciError_ListFailed, "ListFailed" },
        { XciError_NotAnImage, "NotAnImage" },
    };
    int names_ok = 1;
    for (size_t i = 0; i < sizeof(errs) / sizeof(errs[0]); i++) {
        const char *n = xci_error_name(XCI_RESULT(errs[i].desc));
        names_ok = names_ok && n && strcmp(n, errs[i].name) == 0 && xci_error_hint(XCI_RESULT(errs[i].desc));
    }
    chk("every service error has its name and a hint", names_ok);
    chk("result layout: module 505 in bits 0-8", XCI_RESULT(XciError_Busy) == (505u | (4u << 9)));
    chk("foreign result has no name", xci_error_name(0x2A2) == NULL && xci_error_name(0) == NULL);
    chk("unknown 505 description has no name", xci_error_name(XCI_RESULT(99)) == NULL);
    xci_error_describe(XCI_RESULT(XciError_GameCardInUse), buf, sizeof(buf));
    chk("describe: name and hint", strcmp(buf, "GameCardInUse: close the game card title first") == 0);
    xci_error_describe(0x2A2, buf, sizeof(buf));
    chk("describe: foreign result as hex", strcmp(buf, "error 0x2a2") == 0);

    // List: order, current marker, labels.
    static xci_catalog_t cat;
    chk("scan", xci_catalog_scan(&g_fs, "sdmc:/switch/CardLoader/", &cat) == 0);
    chk("scan: 4 images, sorted byte-wise, dot files skipped", cat.count == 4 &&
        strcmp(cat.entries[0].name, "Mario.xci") == 0 && strcmp(cat.entries[1].name, "alone") == 0 &&
        strcmp(cat.entries[2].name, "digimon") == 0 && strcmp(cat.entries[3].name, "zelda.xci") == 0);
    chk("no current image yet", xci_current_index(cat.entries, cat.count) == -1);

    xci_server_t srv;
    xci_server_init(&srv, &g_fs, "sdmc:/switch/CardLoader");
    srv.cur.open = true;               /* as after booting "digimon" */
    xci_resolve(srv.dir, "digimon", &srv.cur.ref);
    xci_server_mark_current(&srv, &cat);
    chk("current marker on the split pair", xci_current_index(cat.entries, cat.count) == 2);
    xci_entry_label(&cat.entries[2], buf, sizeof(buf));
    chk("current label is starred", strcmp(buf, "* digimon") == 0);
    xci_entry_label(&cat.entries[3], buf, sizeof(buf));
    chk("other labels are plain", strcmp(buf, "zelda.xci") == 0);
    xci_entry_value(&cat.entries[2], buf, sizeof(buf));
    chk("split value: parts and size", strcmp(buf, "2 parts  6.19 GiB") == 0);
    xci_entry_value(&cat.entries[1], buf, sizeof(buf));
    chk("single value", strcmp(buf, "1 part  16.0 MiB") == 0);
    xci_format_size(0x800, buf, sizeof(buf));
    chk("small size in KiB", strcmp(buf, "2 KiB") == 0);

    // Path handling.
    xci_ref_t ref;
    const char *dir = "sdmc:/switch/CardLoader/";
    chk(".xci is a single file", xci_resolve(dir, "zelda.xci", &ref) == 0 && !ref.split &&
                                 strcmp(ref.path, "sdmc:/switch/CardLoader/zelda.xci") == 0);
    chk(".xc0 names its pair", xci_resolve(dir, "digimon.xc0", &ref) == 0 && ref.split &&
                               strcmp(ref.path, "sdmc:/switch/CardLoader/digimon") == 0);
    chk(".xc1 names its pair", xci_resolve(dir, "digimon.xc1", &ref) == 0 && ref.split &&
                               strcmp(ref.path, "sdmc:/switch/CardLoader/digimon") == 0);
    chk("bare name is a split base", xci_resolve(dir, "digimon", &ref) == 0 && ref.split);
    chk("absolute sdmc path", xci_resolve(dir, "sdmc:/other/game.xci", &ref) == 0 &&
                              strcmp(ref.path, "sdmc:/other/game.xci") == 0);
    chk("relative subdirectory refused", xci_resolve(dir, "a/b.xci", &ref) == XciError_InvalidPath);
    chk("parent directory refused", xci_resolve(dir, "sdmc:/../x.xci", &ref) == XciError_InvalidPath);

    // Card state from GetStatus.
    XciStatus st = status(HH_STAGE_WAKE_SENT, 0, 0, 256);
    chk("booted card is mounted", xci_card_state(&st) == XCI_CARD_MOUNTED &&
                                  strcmp(xci_card_text(XCI_CARD_MOUNTED), "mounted") == 0);
    st = status(HH_STAGE_SWAP_REMOVING, 1, 0, 0);
    chk("stage 9 reads removing", strcmp(xci_card_text(xci_card_state(&st)), "removing") == 0);
    st = status(HH_STAGE_SWAP_DETACHED, 1, 0, 0);
    chk("stage 10 reads removing", xci_card_state(&st) == XCI_CARD_REMOVING);
    st = status(HH_STAGE_SWAP_INSERTING, 1, 1, 0);
    chk("stage 11 reads inserting", strcmp(xci_card_text(xci_card_state(&st)), "inserting") == 0);
    st = status(HH_STAGE_SWAP_INSERTED, 1, 1, 0);
    chk("inserted, FS not reading yet: inserting", xci_card_state(&st) == XCI_CARD_INSERTING);
    st = status(HH_STAGE_SWAP_INSERTED, 1, 1, 256);
    chk("inserted and read: mounted", xci_card_state(&st) == XCI_CARD_MOUNTED);
    st = status(0, 0, 0, -1);
    chk("hook not mapped: starting", xci_card_state(&st) == XCI_CARD_UNKNOWN);

    // Select flow: refused, then recovered.
    xci_sel_t sel;
    xci_sel_init(&sel);
    chk("idle can start", xci_sel_can_start(&sel));
    xci_sel_start(&sel, "zelda.xci");
    chk("running blocks a second select", !xci_sel_can_start(&sel));
    st = status(HH_STAGE_WAKE_SENT, 0, 0, 256);
    xci_sel_finish(&sel, XCI_RESULT(XciError_GameCardInUse), &st);
    chk("GameCardInUse: failed, message names the error",
        sel.phase == XCI_SEL_FAILED && strstr(sel.message, "GameCardInUse") != NULL);
    xci_sel_poll(&sel, &st);
    chk("refusal is sticky until the next select", sel.phase == XCI_SEL_FAILED);
    chk("refused select leaves the UI usable", xci_sel_can_start(&sel));
    chk("the card is untouched", xci_card_state(&st) == XCI_CARD_MOUNTED);

    xci_sel_start(&sel, "zelda.xci");
    xci_sel_finish(&sel, XCI_RESULT(XciError_Busy), &st);
    chk("Busy: failed and retryable", sel.phase == XCI_SEL_FAILED && strstr(sel.message, "Busy") &&
                                      xci_sel_can_start(&sel));

    // Select flow: accepted swap.
    xci_sel_start(&sel, "zelda.xci");
    st = status(HH_STAGE_WAKE_SENT, 1, 0, 256); /* accepted, hook not started */
    xci_sel_finish(&sel, 0, &st);
    chk("accepted: swapping, generation taken", sel.phase == XCI_SEL_SWAPPING && sel.gen == 1);
    chk("before the hook starts it shows removing", strstr(sel.message, "removing") != NULL);
    chk("swapping blocks a second select", !xci_sel_can_start(&sel));
    st = status(HH_STAGE_SWAP_REMOVING, 1, 0, 0);
    xci_sel_poll(&sel, &st);
    chk("stage 9: removing", sel.phase == XCI_SEL_SWAPPING && strstr(sel.message, "removing"));
    st = status(HH_STAGE_SWAP_INSERTING, 1, 1, 0);
    xci_sel_poll(&sel, &st);
    chk("stage 11: inserting", sel.phase == XCI_SEL_SWAPPING && strstr(sel.message, "inserting"));
    st = status(HH_STAGE_SWAP_TIMEOUT, 1, 0, 0);
    xci_sel_poll(&sel, &st);
    chk("timeout keeps waiting", sel.phase == XCI_SEL_SWAPPING && strstr(sel.message, "sysmodule"));
    st = status(HH_STAGE_SWAP_INSERTED, 1, 1, 0);
    xci_sel_poll(&sel, &st);
    chk("inserted: done, new selections allowed", sel.phase == XCI_SEL_DONE &&
                                                  strcmp(sel.message, "now: zelda.xci") == 0 &&
                                                  xci_sel_can_start(&sel));

    xci_sel_start(&sel, "broken.xci");
    st = status(HH_STAGE_WAKE_SENT, 2, 1, 256);
    xci_sel_finish(&sel, 0, &st);
    st = status(HH_STAGE_SWAP_FAILED, 2, 2, -1);
    xci_sel_poll(&sel, &st);
    chk("rejected image: failed with the stage", sel.phase == XCI_SEL_FAILED &&
                                                 strstr(sel.message, "image rejected") && xci_sel_can_start(&sel));

    // GUI header: "Game Title" and "Location, Size".
    const char *lib = "sdmc:/switch/CardLoader/";
    xci_entry_title(&cat.entries[3], buf, sizeof(buf));
    chk("title drops .xci", strcmp(buf, "zelda") == 0);
    xci_entry_title(&cat.entries[2], buf, sizeof(buf));
    chk("split title is the base", strcmp(buf, "digimon") == 0);
    xci_entry_subtitle(lib, &cat.entries[2], buf, sizeof(buf));
    chk("split subtitle: both parts, size", strcmp(buf, "sdmc:/switch/CardLoader/digimon.xc0 + .xc1, 6.19 GiB") == 0);
    xci_entry_subtitle(lib, &cat.entries[1], buf, sizeof(buf));
    chk("lone .xc0 subtitle", strcmp(buf, "sdmc:/switch/CardLoader/alone.xc0, 16.0 MiB") == 0);
    xci_entry_subtitle(lib, &cat.entries[3], buf, sizeof(buf));
    chk("xci subtitle", strcmp(buf, "sdmc:/switch/CardLoader/zelda.xci, 1.00 GiB") == 0);

    // Carousel: 4 whole tiles on screen.
    chk("fewer images than slots never scroll", xci_carousel_first(3, 2, 4, 0.0f) == 0.0f);
    chk("selection inside the view keeps it", xci_carousel_first(10, 3, 4, 0.0f) == 0.0f);
    chk("stepping past the right edge scrolls by one", xci_carousel_first(10, 4, 4, 0.0f) == 1.0f);
    chk("jumping right puts the selection last", xci_carousel_first(10, 8, 4, 0.0f) == 5.0f);
    chk("never past the last full page", xci_carousel_first(10, 9, 4, 9.0f) == 6.0f);
    chk("stepping left of the view scrolls to it", xci_carousel_first(10, 2, 4, 5.0f) == 2.0f);
    chk("mid-animation offsets round to the settled page", xci_carousel_first(10, 5, 4, 1.6f) == 2.0f);

    if (fails)
        printf("%d failure(s)\n", fails);
    else
        printf("PASS\n");
    return fails ? 1 : 0;
}
