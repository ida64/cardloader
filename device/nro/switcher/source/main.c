/* CardLoader: the xci sysmodule's image library as a row of game tiles.
 *
 *   Title of the highlighted game, its location and size above a carousel
 *   of icons that scrolls on as the selection moves.
 *
 *   Left/Right move (hold to repeat)   L/R  page
 *   A          insert the highlighted game (hot swap)
 *   Y          refresh                 + or B  exit
 *
 * List and select IPC run on one worker thread, reading icons and titles out
 * of the image files on another; the frame loop only reads GetStatus, which
 * takes no lock in the sysmodule. */
#include <stdio.h>
#include <string.h>
#include <switch.h>
#include <SDL.h>

#include "art.h"
#include "gfx.h"
#include "xci_client.h"
#include "xci_view.h"

#define MARGIN      96
#define TITLE_Y     88
#define SUB_Y       152
#define ROW_Y       300
#define TILE        256
#define TILE_R      28
#define GAP         32
#define VISIBLE     4   /* whole tiles on screen; a fifth peeks in */
#define BAR_Y       648
#define POLL_FRAMES 15  /* GetStatus every ~250 ms */

static const SDL_Color BG      = { 0xF2, 0xF2, 0xF2, 255 };
static const SDL_Color INK     = { 0x22, 0x22, 0x22, 255 };
static const SDL_Color MUTED   = { 0x74, 0x74, 0x74, 255 };
static const SDL_Color LINE    = { 0xD2, 0xD2, 0xD2, 255 };
static const SDL_Color EDGE    = { 0xCC, 0xCC, 0xCC, 255 };
static const SDL_Color ACCENT  = { 0x00, 0xBE, 0xE6, 255 };
static const SDL_Color SHADOW  = { 0x00, 0x00, 0x00, 40 };
static const SDL_Color BADGE   = { 0x00, 0x00, 0x00, 170 };
static const SDL_Color WHITE   = { 0xFF, 0xFF, 0xFF, 255 };
static const SDL_Color OK      = { 0x2E, 0xA0, 0x5C, 255 };
static const SDL_Color PENDING = { 0xF0, 0x8C, 0x00, 255 };
static const SDL_Color BAD     = { 0xE6, 0x00, 0x12, 255 };

typedef struct {
    XciImageEntry e;
    char base[XCI_NAME_MAX];   /* name without .xci: art and title key */
    char title[128];
    SDL_Texture *art;
    bool art_tried;
    bool title_cached;         /* title came from the game itself */
    bool extract_tried;        /* art_extract ran for this image */
} tile_t;

static gfx_t g_gfx;
static tile_t g_tiles[XCI_MAX_IMAGES];
static u32 g_count;
static u32 g_cursor;
static float g_first, g_first_shown;
static char g_library[XCI_PATH_MAX];
static char g_note[160];
static bool g_loaded;
static xci_sel_t g_sel;
static XciStatus g_status;
static bool g_have_status;
static keys_t g_keys;
static int g_keys_state;       /* 0 not tried, 1 ready, -1 unavailable */

typedef enum { JOB_NONE, JOB_LIST, JOB_SELECT, JOB_ART } job_t;

typedef struct {
    SDL_Thread *thread;
    SDL_atomic_t done;
    job_t job;
} worker_t;

static worker_t g_ipc, g_art;

static struct {               /* g_ipc's job */
    u32 index;
    Result rc;
    XciImageEntry entries[XCI_MAX_IMAGES];
    u32 total;
    char library[XCI_PATH_MAX];
} g_list;

static struct {               /* g_art's job */
    XciImageEntry e;
    char base[XCI_NAME_MAX];
    char library[XCI_PATH_MAX];
    int rc;
} g_extract;

static int worker_main(void *arg)
{
    worker_t *w = arg;
    switch (w->job) {
    case JOB_LIST:
        g_list.total = 0;
        g_list.rc = xciListImages(g_list.entries, XCI_MAX_IMAGES, &g_list.total);
        xciGetLibraryPath(g_list.library, sizeof(g_list.library));
        break;
    case JOB_SELECT:
        g_list.rc = xciSelectImageByIndex(g_list.index);
        break;
    case JOB_ART:
        if (g_keys_state == 0)
            g_keys_state = keys_init(&g_keys) ? 1 : -1;
        g_extract.rc = g_keys_state > 0
            ? art_extract(&g_keys, g_extract.library, &g_extract.e, g_extract.base)
            : GC_NCA_ERR_KEY;
        break;
    default:
        break;
    }
    SDL_AtomicSet(&w->done, 1);
    return 0;
}

static bool worker_busy(const worker_t *w)
{
    return w->thread != NULL;
}

/* stack: the art job parses HFS0 headers into 64 KiB on the stack. */
static bool worker_start(worker_t *w, job_t job, size_t stack)
{
    if (worker_busy(w))
        return false;
    w->job = job;
    SDL_AtomicSet(&w->done, 0);
    w->thread = stack ? SDL_CreateThreadWithStackSize(worker_main, "xci-art", stack, w)
                      : SDL_CreateThread(worker_main, "xci-ipc", w);
    return w->thread != NULL;
}

/* Returns the finished job once, else JOB_NONE. */
static job_t worker_collect(worker_t *w)
{
    if (!worker_busy(w) || !SDL_AtomicGet(&w->done))
        return JOB_NONE;
    SDL_WaitThread(w->thread, NULL);
    w->thread = NULL;
    return w->job;
}

static void tile_init(tile_t *t, const XciImageEntry *e)
{
    memset(t, 0, sizeof(*t));
    t->e = *e;
    xci_entry_title(e, t->base, sizeof(t->base));
    snprintf(t->title, sizeof(t->title), "%s", t->base);
}

/* Replaces the list, keeping loaded art and the cursor's game where the
 * names still match. */
static void apply_list(void)
{
    g_loaded = true;
    if (R_FAILED(g_list.rc)) {
        xci_error_describe(g_list.rc, g_note, sizeof(g_note));
        return;
    }
    g_note[0] = 0;
    static tile_t fresh[XCI_MAX_IMAGES];
    const u32 count = g_list.total < XCI_MAX_IMAGES ? g_list.total : XCI_MAX_IMAGES;
    char cursor_name[XCI_NAME_MAX] = "";
    if (g_cursor < g_count)
        snprintf(cursor_name, sizeof(cursor_name), "%s", g_tiles[g_cursor].e.name);

    for (u32 i = 0; i < count; i++) {
        tile_t *t = &fresh[i];
        tile_init(t, &g_list.entries[i]);
        u32 j = 0;
        while (j < g_count && strcmp(g_tiles[j].e.name, t->e.name) != 0)
            j++;
        if (j < g_count) {
            t->art = g_tiles[j].art;
            t->art_tried = g_tiles[j].art_tried;
            t->title_cached = g_tiles[j].title_cached;
            t->extract_tried = g_tiles[j].extract_tried;
            snprintf(t->title, sizeof(t->title), "%s", g_tiles[j].title);
            g_tiles[j].art = NULL;
        } else {
            /* Titles up front (small files) so extraction knows what is
             * missing; pictures load lazily as tiles come into view. */
            t->title_cached = art_load_title(t->base, t->title, sizeof(t->title));
            if (!t->title_cached)
                snprintf(t->title, sizeof(t->title), "%s", t->base);
        }
    }
    for (u32 j = 0; j < g_count; j++)
        if (g_tiles[j].art)
            SDL_DestroyTexture(g_tiles[j].art);
    memcpy(g_tiles, fresh, sizeof(tile_t) * count);
    g_count = count;
    snprintf(g_library, sizeof(g_library), "%s", g_list.library);

    /* Cursor: same game as before, else the inserted one, else the first. */
    g_cursor = 0;
    int cur = -1;
    for (u32 i = 0; i < g_count; i++) {
        if (cursor_name[0] && strcmp(g_tiles[i].e.name, cursor_name) == 0)
            g_cursor = i, cur = (int)i;
    }
    if (cur < 0) {
        cur = xci_current_index(g_list.entries, count);
        g_cursor = cur >= 0 ? (u32)cur : 0;
    }
}

/* Loads one missing tile image per frame, nearest the view first. */
static void load_some_art(void)
{
    const int first = (int)g_first_shown - 1;
    for (int i = first < 0 ? 0 : first; i < (int)g_count && i <= first + VISIBLE + 2; i++) {
        tile_t *t = &g_tiles[i];
        if (t->art_tried)
            continue;
        t->art_tried = true;
        SDL_Surface *s = art_load(g_library, t->base);
        if (s) {
            t->art = gfx_round_texture(&g_gfx, s, TILE, TILE_R);
            SDL_FreeSurface(s);
        }
        if (!t->art)
            t->art = gfx_placeholder(&g_gfx, t->title, TILE, TILE_R);
        return;
    }
}

/* Reads the next game whose icon and title are not cached yet out of its
 * image file: the tiles in view first, then the rest. Not during a swap,
 * which has the SD busy and must not meet the brief FS hold in keys_init. */
static void maybe_extract(void)
{
    if (g_keys_state < 0 || worker_busy(&g_art) || worker_busy(&g_ipc) || !xci_sel_can_start(&g_sel) ||
        g_count == 0)
        return;
    u32 start = (u32)g_first_shown;
    if (start >= g_count)
        start = 0;
    for (u32 k = 0; k < g_count; k++) {
        const u32 i = (start + k) % g_count;
        tile_t *t = &g_tiles[i];
        if (t->title_cached || t->extract_tried)
            continue;
        t->extract_tried = true;
        g_extract.e = t->e;
        snprintf(g_extract.base, sizeof(g_extract.base), "%s", t->base);
        snprintf(g_extract.library, sizeof(g_extract.library), "%s", g_library);
        worker_start(&g_art, JOB_ART, 512 * 1024);
        return;
    }
}

static void finish_extract(void)
{
    if (g_keys_state < 0) {
        snprintf(g_note, sizeof(g_note), "Game icons unavailable: %s", g_keys.error);
        return;
    }
    if (g_extract.rc != 0) {
        /* This image keeps its generated tile; say why once. */
        static const char *const why[] = { "", "read error", "no secure partition", "no control data",
                                           "key unavailable", "unexpected layout", "no icon" };
        const int r = -g_extract.rc;
        if (!g_note[0])
            snprintf(g_note, sizeof(g_note), "No icon for %s: %s", g_extract.base,
                     r > 0 && r < (int)(sizeof(why) / sizeof(why[0])) ? why[r] : "error");
        return;
    }
    for (u32 i = 0; i < g_count; i++) {
        tile_t *t = &g_tiles[i];
        if (strcmp(t->base, g_extract.base) != 0)
            continue;
        t->title_cached = art_load_title(t->base, t->title, sizeof(t->title));
        if (!t->title_cached)
            snprintf(t->title, sizeof(t->title), "%s", t->base);
        if (t->art)
            SDL_DestroyTexture(t->art);
        t->art = NULL;
        t->art_tried = false; /* reloaded from the cache next frame */
    }
}

static void move_cursor(int delta)
{
    if (g_count == 0)
        return;
    int c = (int)g_cursor + delta;
    if (c < 0)
        c = 0;
    if (c >= (int)g_count)
        c = (int)g_count - 1;
    g_cursor = (u32)c;
}

static void request_select(void)
{
    if (g_cursor >= g_count)
        return;
    if (!xci_sel_can_start(&g_sel) || worker_busy(&g_ipc)) {
        xci_error_describe(XCI_RESULT(XciError_Busy), g_note, sizeof(g_note));
        return;
    }
    g_note[0] = 0;
    xci_sel_start(&g_sel, g_tiles[g_cursor].e.name);
    g_list.index = g_cursor;
    worker_start(&g_ipc, JOB_SELECT, 0);
}

static void request_list(void)
{
    if (!worker_start(&g_ipc, JOB_LIST, 0))
        xci_error_describe(XCI_RESULT(XciError_Busy), g_note, sizeof(g_note));
}

static void triangle(int x, int y, int size, bool right, SDL_Color c)
{
    const float d = right ? (float)size : -(float)size;
    SDL_Vertex v[3] = {
        { { (float)x, (float)(y - size) }, c, { 0, 0 } },
        { { (float)x, (float)(y + size) }, c, { 0, 0 } },
        { { (float)x + d, (float)y }, c, { 0, 0 } },
    };
    SDL_RenderGeometry(g_gfx.ren, NULL, v, 3, NULL, 0);
}

static void badge(int x, int y, const char *text)
{
    const int w = gfx_text_width(&g_gfx, FONT_SMALL, text) + 24;
    gfx_round_rect(&g_gfx, x, y, w, 32, 16, BADGE);
    gfx_text(&g_gfx, FONT_SMALL, text, x + 12, y + 16 - gfx_font_height(&g_gfx, FONT_SMALL) / 2, WHITE, ALIGN_LEFT, 0);
}

static void draw_tile(const tile_t *t, int x, bool selected, bool target)
{
    const int y = ROW_Y - (selected ? 8 : 0);
    const int b = selected ? 6 : 2;
    gfx_round_rect(&g_gfx, x + 2, y + 10, TILE, TILE, TILE_R, SHADOW);
    gfx_round_rect(&g_gfx, x - b, y - b, TILE + 2 * b, TILE + 2 * b, TILE_R + b, selected ? ACCENT : EDGE);
    if (t->art) {
        SDL_Rect dst = { x, y, TILE, TILE };
        SDL_RenderCopy(g_gfx.ren, t->art, NULL, &dst);
    } else {
        gfx_round_rect(&g_gfx, x, y, TILE, TILE, TILE_R, WHITE);
    }
    if (target)
        badge(x + 14, y + TILE - 46, "Inserting\xE2\x80\xA6");
    else if (t->e.flags & XCI_IMAGE_FLAG_CURRENT)
        badge(x + 14, y + TILE - 46, "Inserted");
}

/* Button hints, right-aligned: glyph (NintendoExt) then label. */
static void hints(int right, int y)
{
    static const struct { const char *glyph, *label; } h[] = {
        { "\uE0A0", "Insert" }, { "\uE0A3", "Refresh" }, { "\uE0B5", "Exit" },
    };
    int x = right;
    for (int i = (int)(sizeof(h) / sizeof(h[0])) - 1; i >= 0; i--) {
        x -= gfx_text(&g_gfx, FONT_BODY, h[i].label, x, y, INK, ALIGN_RIGHT, 0);
        x -= 8;
        x -= gfx_text(&g_gfx, FONT_GLYPH, h[i].glyph, x, y, INK, ALIGN_RIGHT, 0);
        x -= 36;
    }
}

/* Bottom-left: which game the card holds and what FS is doing with it. */
static void draw_status(int x, int y)
{
    if (!g_have_status)
        return;
    const xci_card_t card = xci_card_state(&g_status);
    const SDL_Color dot = card == XCI_CARD_MOUNTED ? OK
                        : card == XCI_CARD_FAILED ? BAD
                        : card == XCI_CARD_NONE || card == XCI_CARD_UNKNOWN ? MUTED : PENDING;
    char text[200];
    int cur = -1;
    for (u32 i = 0; i < g_count; i++)
        if (g_tiles[i].e.flags & XCI_IMAGE_FLAG_CURRENT)
            cur = (int)i;
    if (cur >= 0)
        snprintf(text, sizeof(text), "Card %s  \xC2\xB7  %s", xci_card_text(card), g_tiles[cur].title);
    else
        snprintf(text, sizeof(text), "Card: %s", xci_card_text(card));
    gfx_round_rect(&g_gfx, x, y + gfx_font_height(&g_gfx, FONT_BODY) / 2 - 6, 12, 12, 6, dot);
    gfx_text(&g_gfx, FONT_BODY, text, x + 22, y, MUTED, ALIGN_LEFT, 560);
}

/* "Keeps going": a round button with an arrow over the row's edge. */
static void scroll_hint(int cx, int cy, bool right)
{
    gfx_round_rect(&g_gfx, cx - 26, cy - 22, 52, 52, 26, SHADOW);
    gfx_round_rect(&g_gfx, cx - 26, cy - 26, 52, 52, 26, WHITE);
    triangle(right ? cx - 6 : cx + 6, cy, 11, right, INK);
}

static void draw(void)
{
    gfx_begin(&g_gfx, BG);

    if (g_count == 0) {
        gfx_text(&g_gfx, FONT_TITLE, g_loaded ? "No games" : "Loading\xE2\x80\xA6", MARGIN, TITLE_Y, INK, ALIGN_LEFT, 0);
        if (g_loaded) {
            char where[XCI_PATH_MAX + 64];
            snprintf(where, sizeof(where), "Put .xci or .xc0 + .xc1 files in %s and press \xE2\x80\x9CRefresh\xE2\x80\x9D", g_library);
            gfx_text(&g_gfx, FONT_SUB, where, MARGIN, SUB_Y, MUTED, ALIGN_LEFT, GFX_W - 2 * MARGIN);
        }
        if (g_note[0])
            gfx_text(&g_gfx, FONT_BODY, g_note, MARGIN, ROW_Y + TILE + 40, BAD, ALIGN_LEFT, GFX_W - 2 * MARGIN);
    } else {
        const tile_t *sel = &g_tiles[g_cursor];
        char sub[XCI_PATH_MAX + XCI_NAME_MAX + 32];
        xci_entry_subtitle(g_library, &sel->e, sub, sizeof(sub));
        gfx_text(&g_gfx, FONT_TITLE, sel->title, MARGIN, TITLE_Y, INK, ALIGN_LEFT, GFX_W - 2 * MARGIN);
        gfx_text(&g_gfx, FONT_SUB, sub, MARGIN, SUB_Y, MUTED, ALIGN_LEFT, GFX_W - 2 * MARGIN);

        for (u32 i = 0; i < g_count; i++) {
            const int x = MARGIN + (int)((i - g_first_shown) * (TILE + GAP));
            if (x > GFX_W || x + TILE < 0)
                continue;
            const bool target = g_sel.phase == XCI_SEL_SWAPPING && strcmp(g_sel.name, g_tiles[i].e.name) == 0;
            if (i != g_cursor)
                draw_tile(&g_tiles[i], x, false, target);
        }
        /* The selection last, so its border sits on top of its neighbours. */
        const int sx = MARGIN + (int)((g_cursor - g_first_shown) * (TILE + GAP));
        draw_tile(sel, sx, true, g_sel.phase == XCI_SEL_SWAPPING && strcmp(g_sel.name, sel->e.name) == 0);

        /* "Keeps going": arrows while more tiles lie off screen. */
        const int mid = ROW_Y + TILE / 2;
        if (g_first_shown + VISIBLE < g_count - 0.01f)
            scroll_hint(GFX_W - 48, mid, true);
        if (g_first_shown > 0.01f)
            scroll_hint(48, mid, false);

        /* Position, then the select progress or the last error. */
        char pos[32];
        snprintf(pos, sizeof(pos), "%u / %u", g_cursor + 1, g_count);
        const int below = ROW_Y + TILE + 40;
        const int pw = gfx_text(&g_gfx, FONT_BODY, pos, MARGIN, below, MUTED, ALIGN_LEFT, 0);
        const char *msg = g_note[0] ? g_note : g_sel.message;
        const SDL_Color msg_color = g_note[0] || g_sel.phase == XCI_SEL_FAILED ? BAD : INK;
        gfx_text(&g_gfx, FONT_BODY, msg, MARGIN + pw + 32, below, msg_color, ALIGN_LEFT, GFX_W - 2 * MARGIN - pw - 32);
    }

    SDL_SetRenderDrawColor(g_gfx.ren, LINE.r, LINE.g, LINE.b, 255);
    SDL_RenderDrawLine(g_gfx.ren, MARGIN / 2, BAR_Y, GFX_W - MARGIN / 2, BAR_Y);
    draw_status(MARGIN / 2 + 8, BAR_Y + 22);
    hints(GFX_W - MARGIN / 2 - 8, BAR_Y + 22);

    gfx_end(&g_gfx);
}

static void error_screen(const char *line1, const char *line2, PadState *pad)
{
    while (appletMainLoop()) {
        padUpdate(pad);
        if (padGetButtonsDown(pad) & (HidNpadButton_Plus | HidNpadButton_B))
            break;
        gfx_begin(&g_gfx, BG);
        gfx_text(&g_gfx, FONT_TITLE, line1, MARGIN, TITLE_Y, INK, ALIGN_LEFT, GFX_W - 2 * MARGIN);
        gfx_text(&g_gfx, FONT_SUB, line2, MARGIN, SUB_Y, MUTED, ALIGN_LEFT, GFX_W - 2 * MARGIN);
        hints(GFX_W - MARGIN / 2 - 8, BAR_Y + 22);
        gfx_end(&g_gfx);
    }
}

int main(void)
{
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);
    if (!gfx_init(&g_gfx)) {
        gfx_exit(&g_gfx);
        return 1;
    }
    xci_sel_init(&g_sel);

    const Result rc = xciInitialize();
    if (R_FAILED(rc)) {
        char why[96];
        snprintf(why, sizeof(why), "xci service unavailable (0x%x): is the xci sysmodule installed?", rc);
        error_screen("CardLoader", why, &pad);
        gfx_exit(&g_gfx);
        return 0;
    }
    request_list();

    int repeat = 0;
    u32 frames = 0;
    while (appletMainLoop()) {
        padUpdate(&pad);
        const u64 down = padGetButtonsDown(&pad);
        const u64 held = padGetButtons(&pad);
        if (down & (HidNpadButton_Plus | HidNpadButton_B))
            break;

        /* Left/Right with hold-to-repeat (400 ms, then every 100 ms). */
        const int dir = (held & HidNpadButton_AnyRight) ? 1 : (held & HidNpadButton_AnyLeft) ? -1 : 0;
        if (down & (HidNpadButton_AnyRight | HidNpadButton_AnyLeft)) {
            move_cursor(dir);
            repeat = 24;
        } else if (dir != 0 && --repeat <= 0) {
            move_cursor(dir);
            repeat = 6;
        }
        if (down & HidNpadButton_R)
            move_cursor(VISIBLE);
        if (down & HidNpadButton_L)
            move_cursor(-VISIBLE);
        if (down & HidNpadButton_A)
            request_select();
        if (down & HidNpadButton_Y)
            request_list();

        switch (worker_collect(&g_ipc)) {
        case JOB_LIST:
            apply_list();
            break;
        case JOB_SELECT: {
            XciStatus st = {0};
            xciGetStatus(&st);
            xci_sel_finish(&g_sel, g_list.rc, &st);
            frames = POLL_FRAMES - 1; /* poll on the next line */
            break;
        }
        default:
            break;
        }
        if (worker_collect(&g_art) == JOB_ART)
            finish_extract();

        if (++frames >= POLL_FRAMES) {
            frames = 0;
            g_have_status = R_SUCCEEDED(xciGetStatus(&g_status));
            if (g_have_status) {
                const xci_sel_phase_t before = g_sel.phase;
                xci_sel_poll(&g_sel, &g_status);
                /* A finished swap moves the Inserted badge. */
                if (before == XCI_SEL_SWAPPING && g_sel.phase != XCI_SEL_SWAPPING)
                    request_list();
            }
        }
        maybe_extract();

        g_first = xci_carousel_first(g_count, g_cursor, VISIBLE, g_first);
        g_first_shown += (g_first - g_first_shown) * 0.25f;
        if (SDL_fabsf(g_first - g_first_shown) < 0.002f)
            g_first_shown = g_first;
        load_some_art();
        draw();
    }

    while (worker_busy(&g_ipc) || worker_busy(&g_art)) {
        SDL_Delay(10);
        worker_collect(&g_ipc);
        worker_collect(&g_art);
    }
    keys_exit(&g_keys);
    for (u32 i = 0; i < g_count; i++)
        if (g_tiles[i].art)
            SDL_DestroyTexture(g_tiles[i].art);
    xciExit();
    gfx_exit(&g_gfx);
    return 0;
}
