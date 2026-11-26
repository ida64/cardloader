/* gfx.c - see gfx.h. */
#include "gfx.h"

#include <math.h>
#include <string.h>
#include <switch.h>

static const int g_font_size[FONT_COUNT] = { 46, 24, 22, 18, 88, 24, 44 };

static PlFontData g_std, g_ext;

static TTF_Font *open_shared(const PlFontData *f, int size)
{
    SDL_RWops *rw = SDL_RWFromConstMem(f->address, (int)f->size);
    return rw ? TTF_OpenFontRW(rw, 1, size) : NULL;
}

bool gfx_init(gfx_t *g)
{
    memset(g, 0, sizeof(*g));
    if (SDL_Init(SDL_INIT_VIDEO) != 0 || TTF_Init() != 0)
        return false;
    g->window = SDL_CreateWindow("CardLoader", 0, 0, GFX_W, GFX_H, 0);
    if (!g->window)
        return false;
    g->ren = SDL_CreateRenderer(g->window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!g->ren)
        return false;
    SDL_SetRenderDrawBlendMode(g->ren, SDL_BLENDMODE_BLEND);

    if (R_FAILED(plInitialize(PlServiceType_User)) ||
        R_FAILED(plGetSharedFontByType(&g_std, PlSharedFontType_Standard)) ||
        R_FAILED(plGetSharedFontByType(&g_ext, PlSharedFontType_NintendoExt)))
        return false;
    for (int i = 0; i < FONT_COUNT; i++) {
        const bool ext = i == FONT_GLYPH || i == FONT_CHEVRON;
        g->font[i] = open_shared(ext ? &g_ext : &g_std, g_font_size[i]);
        if (!g->font[i])
            return false;
    }
    return true;
}

#define TEXT_CACHE 64

typedef struct {
    int font, max_w;
    Uint32 rgba;
    char key[160];
    SDL_Texture *tex;
    int w, h;
    unsigned used;
} text_entry_t;

static text_entry_t g_text[TEXT_CACHE];

static Uint32 pack(SDL_Color c)
{
    return (Uint32)c.r << 24 | (Uint32)c.g << 16 | (Uint32)c.b << 8 | c.a;
}

int gfx_text_width(gfx_t *g, int font, const char *text)
{
    int w = 0, h = 0;
    TTF_SizeUTF8(g->font[font], text, &w, &h);
    return w;
}

int gfx_font_height(gfx_t *g, int font)
{
    return TTF_FontHeight(g->font[font]);
}

/* Cuts whole UTF-8 characters off the end and appends an ellipsis until
 * the text fits max_w. */
static void fit(gfx_t *g, int font, const char *text, int max_w, char *out, size_t n)
{
    snprintf(out, n, "%s", text);
    if (max_w <= 0 || gfx_text_width(g, font, out) <= max_w)
        return;
    size_t len = strlen(out);
    while (len > 0) {
        do {
            len--;
        } while (len > 0 && ((unsigned char)out[len] & 0xC0) == 0x80);
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%.*s\xE2\x80\xA6", (int)len, out);
        if (gfx_text_width(g, font, tmp) <= max_w) {
            snprintf(out, n, "%s", tmp);
            return;
        }
    }
    out[0] = 0;
}

int gfx_text(gfx_t *g, int font, const char *text, int x, int y, SDL_Color c, int align, int max_w)
{
    if (!text || !text[0])
        return 0;
    const Uint32 rgba = pack(c);
    text_entry_t *e = NULL, *victim = &g_text[0];
    if (strlen(text) < sizeof(g_text[0].key)) {
        for (int i = 0; i < TEXT_CACHE; i++) {
            text_entry_t *t = &g_text[i];
            if (t->tex && t->font == font && t->rgba == rgba && t->max_w == max_w && strcmp(t->key, text) == 0) {
                e = t;
                break;
            }
            if (!t->tex || t->used < victim->used)
                victim = t;
        }
    }
    SDL_Texture *tex = NULL;
    int w = 0, h = 0;
    if (e) {
        tex = e->tex;
        w = e->w;
        h = e->h;
        e->used = g->frame;
    } else {
        char shown[512];
        fit(g, font, text, max_w, shown, sizeof(shown));
        if (!shown[0])
            return 0;
        SDL_Surface *s = TTF_RenderUTF8_Blended(g->font[font], shown, c);
        if (!s)
            return 0;
        tex = SDL_CreateTextureFromSurface(g->ren, s);
        w = s->w;
        h = s->h;
        SDL_FreeSurface(s);
        if (!tex)
            return 0;
        if (strlen(text) < sizeof(victim->key)) {
            if (victim->tex)
                SDL_DestroyTexture(victim->tex);
            *victim = (text_entry_t){ font, max_w, rgba, "", tex, w, h, g->frame };
            snprintf(victim->key, sizeof(victim->key), "%s", text);
        }
    }
    if (align == ALIGN_RIGHT)
        x -= w;
    else if (align == ALIGN_CENTER)
        x -= w / 2;
    SDL_Rect dst = { x, y, w, h };
    SDL_RenderCopy(g->ren, tex, NULL, &dst);
    if (!e && strlen(text) >= sizeof(g_text[0].key))
        SDL_DestroyTexture(tex);
    return w;
}

/* Coverage of pixel (x, y) by a size_w x size_h rounded rectangle. */
static float coverage(int x, int y, int w, int h, int r)
{
    const float px = x + 0.5f, py = y + 0.5f;
    float cx, cy;
    if (px < r)
        cx = (float)r;
    else if (px > w - r)
        cx = (float)(w - r);
    else
        return 1.0f;
    if (py < r)
        cy = (float)r;
    else if (py > h - r)
        cy = (float)(h - r);
    else
        return 1.0f;
    const float d = sqrtf((px - cx) * (px - cx) + (py - cy) * (py - cy));
    const float c = r - d + 0.5f;
    return c < 0.0f ? 0.0f : c > 1.0f ? 1.0f : c;
}

static void mask_corners(SDL_Surface *s, int r)
{
    SDL_LockSurface(s);
    for (int y = 0; y < s->h; y++) {
        Uint8 *row = (Uint8 *)s->pixels + (size_t)y * s->pitch;
        for (int x = 0; x < s->w; x++) {
            const float c = coverage(x, y, s->w, s->h, r);
            if (c < 1.0f)
                row[x * 4 + 3] = (Uint8)(row[x * 4 + 3] * c);
        }
    }
    SDL_UnlockSurface(s);
}

static SDL_Texture *to_texture(gfx_t *g, SDL_Surface *s)
{
    SDL_Texture *t = SDL_CreateTextureFromSurface(g->ren, s);
    if (t)
        SDL_SetTextureBlendMode(t, SDL_BLENDMODE_BLEND);
    return t;
}

/* White quarter disc of radius r (top-left corner), anti-aliased; tinted
 * and flipped for every corner of gfx_round_rect. */
#define CORNER_CACHE 8
static struct { int r; SDL_Texture *tex; } g_corner[CORNER_CACHE];

static SDL_Texture *corner(gfx_t *g, int r)
{
    for (int i = 0; i < CORNER_CACHE; i++)
        if (g_corner[i].tex && g_corner[i].r == r)
            return g_corner[i].tex;
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 2 * r, 2 * r, 32, SDL_PIXELFORMAT_RGBA32);
    if (!s)
        return NULL;
    SDL_FillRect(s, NULL, SDL_MapRGBA(s->format, 255, 255, 255, 255));
    mask_corners(s, r);
    SDL_Rect quarter = { 0, 0, r, r };
    SDL_Surface *q = SDL_CreateRGBSurfaceWithFormat(0, r, r, 32, SDL_PIXELFORMAT_RGBA32);
    SDL_SetSurfaceBlendMode(s, SDL_BLENDMODE_NONE);
    SDL_BlitSurface(s, &quarter, q, NULL);
    SDL_FreeSurface(s);
    SDL_Texture *t = to_texture(g, q);
    SDL_FreeSurface(q);
    for (int i = 0; i < CORNER_CACHE; i++) {
        if (!g_corner[i].tex) {
            g_corner[i].r = r;
            g_corner[i].tex = t;
            return t;
        }
    }
    SDL_DestroyTexture(g_corner[0].tex);
    g_corner[0].r = r;
    g_corner[0].tex = t;
    return t;
}

void gfx_round_rect(gfx_t *g, int x, int y, int w, int h, int r, SDL_Color c)
{
    if (r * 2 > w)
        r = w / 2;
    if (r * 2 > h)
        r = h / 2;
    SDL_SetRenderDrawColor(g->ren, c.r, c.g, c.b, c.a);
    SDL_Rect mid = { x + r, y, w - 2 * r, h };
    SDL_Rect left = { x, y + r, r, h - 2 * r };
    SDL_Rect right = { x + w - r, y + r, r, h - 2 * r };
    SDL_RenderFillRect(g->ren, &mid);
    SDL_RenderFillRect(g->ren, &left);
    SDL_RenderFillRect(g->ren, &right);
    SDL_Texture *t = corner(g, r);
    if (!t)
        return;
    SDL_SetTextureColorMod(t, c.r, c.g, c.b);
    SDL_SetTextureAlphaMod(t, c.a);
    const SDL_Rect tl = { x, y, r, r }, tr = { x + w - r, y, r, r };
    const SDL_Rect bl = { x, y + h - r, r, r }, br = { x + w - r, y + h - r, r, r };
    SDL_RenderCopyEx(g->ren, t, NULL, &tl, 0, NULL, SDL_FLIP_NONE);
    SDL_RenderCopyEx(g->ren, t, NULL, &tr, 0, NULL, SDL_FLIP_HORIZONTAL);
    SDL_RenderCopyEx(g->ren, t, NULL, &bl, 0, NULL, SDL_FLIP_VERTICAL);
    SDL_RenderCopyEx(g->ren, t, NULL, &br, 0, NULL, (SDL_RendererFlip)(SDL_FLIP_HORIZONTAL | SDL_FLIP_VERTICAL));
}

SDL_Texture *gfx_round_texture(gfx_t *g, SDL_Surface *src, int size, int radius)
{
    SDL_Surface *rgba = SDL_ConvertSurfaceFormat(src, SDL_PIXELFORMAT_RGBA32, 0);
    SDL_Surface *dst = SDL_CreateRGBSurfaceWithFormat(0, size, size, 32, SDL_PIXELFORMAT_RGBA32);
    SDL_Texture *t = NULL;
    if (rgba && dst) {
        /* Cover: the centred square of the source, scaled. */
        const int s = rgba->w < rgba->h ? rgba->w : rgba->h;
        SDL_Rect crop = { (rgba->w - s) / 2, (rgba->h - s) / 2, s, s };
        SDL_SetSurfaceBlendMode(rgba, SDL_BLENDMODE_NONE);
        SDL_BlitScaled(rgba, &crop, dst, NULL);
        mask_corners(dst, radius);
        t = to_texture(g, dst);
    }
    SDL_FreeSurface(rgba);
    SDL_FreeSurface(dst);
    return t;
}

/* Initials: first letters of the first two words, else the first two
 * characters; ASCII upper-cased. */
static void initials(const char *title, char out[8])
{
    int n = 0;
    bool word = true;
    for (const char *p = title; *p && n < 2; p++) {
        const unsigned char ch = (unsigned char)*p;
        if (ch == ' ' || ch == '-' || ch == '_' || ch == '.') {
            word = true;
            continue;
        }
        if (word && ch < 0x80) {
            out[n++] = (char)(ch >= 'a' && ch <= 'z' ? ch - 32 : ch);
            word = false;
        }
    }
    if (n == 1 && title[1] && (unsigned char)title[1] < 0x80 && title[1] != ' ')
        out[n++] = (char)(title[1] >= 'a' && title[1] <= 'z' ? title[1] - 32 : title[1]);
    out[n] = 0;
}

SDL_Texture *gfx_placeholder(gfx_t *g, const char *title, int size, int radius)
{
    static const SDL_Color palette[] = {
        { 0xE6, 0x00, 0x12, 255 }, { 0x00, 0x96, 0xD6, 255 }, { 0x2E, 0xA0, 0x5C, 255 },
        { 0xF0, 0x8C, 0x00, 255 }, { 0x7A, 0x4B, 0xC8, 255 }, { 0x00, 0x9E, 0x96, 255 },
        { 0xD6, 0x3A, 0x7A, 255 }, { 0x4A, 0x5A, 0x6A, 255 },
    };
    unsigned h = 2166136261u;
    for (const char *p = title; *p; p++)
        h = (h ^ (unsigned char)*p) * 16777619u;
    const SDL_Color c = palette[h % (sizeof(palette) / sizeof(palette[0]))];

    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, size, size, 32, SDL_PIXELFORMAT_RGBA32);
    if (!s)
        return NULL;
    for (int y = 0; y < size; y++) {
        const float k = 1.0f - 0.25f * y / size; /* darker towards the bottom */
        SDL_Rect row = { 0, y, size, 1 };
        SDL_FillRect(s, &row, SDL_MapRGBA(s->format, (Uint8)(c.r * k), (Uint8)(c.g * k), (Uint8)(c.b * k), 255));
    }
    char ini[8];
    initials(title, ini);
    if (ini[0]) {
        SDL_Surface *txt = TTF_RenderUTF8_Blended(g->font[FONT_TILE], ini, (SDL_Color){ 255, 255, 255, 255 });
        if (txt) {
            SDL_Rect at = { (size - txt->w) / 2, (size - txt->h) / 2, txt->w, txt->h };
            SDL_SetSurfaceBlendMode(txt, SDL_BLENDMODE_BLEND);
            SDL_BlitSurface(txt, NULL, s, &at);
            SDL_FreeSurface(txt);
        }
    }
    mask_corners(s, radius);
    SDL_Texture *t = to_texture(g, s);
    SDL_FreeSurface(s);
    return t;
}

void gfx_begin(gfx_t *g, SDL_Color bg)
{
    g->frame++;
    SDL_SetRenderDrawColor(g->ren, bg.r, bg.g, bg.b, 255);
    SDL_RenderClear(g->ren);
}

void gfx_end(gfx_t *g)
{
    SDL_RenderPresent(g->ren);
}

void gfx_exit(gfx_t *g)
{
    for (int i = 0; i < TEXT_CACHE; i++)
        if (g_text[i].tex)
            SDL_DestroyTexture(g_text[i].tex);
    for (int i = 0; i < CORNER_CACHE; i++)
        if (g_corner[i].tex)
            SDL_DestroyTexture(g_corner[i].tex);
    for (int i = 0; i < FONT_COUNT; i++)
        if (g->font[i])
            TTF_CloseFont(g->font[i]);
    plExit();
    if (g->ren)
        SDL_DestroyRenderer(g->ren);
    if (g->window)
        SDL_DestroyWindow(g->window);
    TTF_Quit();
    SDL_Quit();
}
