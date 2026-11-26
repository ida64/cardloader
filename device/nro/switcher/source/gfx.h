/* gfx.h - the switcher's drawing layer: SDL2 renderer at 1280x720, the
 * console's shared fonts (pl), cached text, rounded tiles. */
#ifndef SWITCHER_GFX_H
#define SWITCHER_GFX_H

#include <stdbool.h>
#include <SDL.h>
#include <SDL_ttf.h>

#define GFX_W 1280
#define GFX_H 720

enum {
    FONT_TITLE,   /* game title */
    FONT_SUB,     /* "Location, Size" */
    FONT_BODY,    /* status, hints */
    FONT_SMALL,   /* tile badges */
    FONT_TILE,    /* placeholder initials */
    FONT_GLYPH,   /* button glyphs (NintendoExt), body size */
    FONT_CHEVRON, /* scroll arrows (NintendoExt), large */
    FONT_COUNT
};

enum { ALIGN_LEFT, ALIGN_RIGHT, ALIGN_CENTER };

typedef struct {
    SDL_Window *window;
    SDL_Renderer *ren;
    TTF_Font *font[FONT_COUNT];
    unsigned frame;
} gfx_t;

bool gfx_init(gfx_t *g);
void gfx_exit(gfx_t *g);

/* Starts a frame: clears to the background. */
void gfx_begin(gfx_t *g, SDL_Color bg);
void gfx_end(gfx_t *g);

/* Draws UTF-8 text with its top at y; truncated with an ellipsis to max_w
 * when max_w > 0. Returns the drawn width. Textures are cached by content. */
int gfx_text(gfx_t *g, int font, const char *text, int x, int y, SDL_Color c, int align, int max_w);
int gfx_text_width(gfx_t *g, int font, const char *text);
int gfx_font_height(gfx_t *g, int font);

void gfx_round_rect(gfx_t *g, int x, int y, int w, int h, int r, SDL_Color c);

/* A size x size texture with anti-aliased rounded corners from any surface
 * (scaled to fit); the caller keeps ownership of src. */
SDL_Texture *gfx_round_texture(gfx_t *g, SDL_Surface *src, int size, int radius);
/* A generated tile: colour from the title, its initials in the middle. */
SDL_Texture *gfx_placeholder(gfx_t *g, const char *title, int size, int radius);

#endif /* SWITCHER_GFX_H */
