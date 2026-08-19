#ifndef VIDEO_H
#define VIDEO_H

#include <stdint.h>

/* Runtime geometry (set by video_init_gui). Defaults match VESA target. */
extern int video_width;
extern int video_height;
extern int video_pitch;
extern int video_bpp;
extern uint8_t *video_fb;       /* LFB */
extern uint8_t *video_back;     /* software backbuffer (ARGB8888), or NULL */

#define VIDEO_TRANSPARENT 0xFFu

/* Packed RGB helpers (0x00RRGGBB in the low 24 bits; we store as 0xFFRRGGBB). */
static inline uint32_t vid_rgb(uint8_t r, uint8_t g, uint8_t b) {
  return 0xFF000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

/* AJOS identity palette: deep ocean blues + cyan glow. Legacy color names
 * (COL_ORANGE etc.) now map to the blue scheme so all callers restyle. */
#define COL_BG0 vid_rgb(6, 16, 42)
#define COL_BG1 vid_rgb(16, 42, 88)
#define COL_BG_TL vid_rgb(16, 38, 84)
#define COL_BG_TR vid_rgb(10, 24, 58)
#define COL_BG_BL vid_rgb(7, 16, 42)
#define COL_BG_BR vid_rgb(3, 8, 24)
/* accent (was orange) */
#define COL_ORANGE vid_rgb(56, 152, 255)
#define COL_ORANGE_DIM vid_rgb(34, 106, 190)
/* secondary deep indigo (was aubergine) */
#define COL_AUBERGINE vid_rgb(30, 52, 110)
#define COL_TEAL vid_rgb(56, 152, 255) /* accent reuse for caret/focus */
#define COL_TEAL_DIM vid_rgb(34, 106, 190)
#define COL_ACCENT2 vid_rgb(34, 211, 238) /* cyan */
#define COL_PANEL vid_rgb(244, 248, 255)
#define COL_PANEL2 vid_rgb(228, 236, 250)
#define COL_ICON vid_rgb(52, 60, 84)
#define COL_ICON_HI vid_rgb(70, 82, 116)
#define COL_SURFACE vid_rgb(250, 252, 255)
#define COL_EDGE vid_rgb(198, 210, 230)
#define COL_EDGE_HI vid_rgb(56, 152, 255)
#define COL_TEXT vid_rgb(28, 36, 54)
#define COL_TEXT_DIM vid_rgb(112, 126, 150)
#define COL_TEXT_INV vid_rgb(240, 247, 255)
#define COL_TITLE vid_rgb(238, 244, 254)
#define COL_CLOSE vid_rgb(232, 72, 60)
#define COL_MIN vid_rgb(56, 152, 255)
#define COL_MAX vid_rgb(46, 180, 90)
#define COL_TASKBAR vid_rgb(10, 18, 38)
#define COL_TASK_BTN vid_rgb(20, 34, 64)
#define COL_DOCK vid_rgb(8, 16, 36)
#define COL_MENUBAR vid_rgb(8, 16, 36)
#define COL_CURSOR vid_rgb(56, 152, 255)
#define COL_BLACK vid_rgb(0, 0, 0)
#define COL_TERM_BG vid_rgb(6, 14, 34)
#define COL_TERM_FG vid_rgb(226, 238, 255)

#ifndef AJOS_SERIAL_ONLY
/* Carve a contiguous ARGB backbuffer from PMM while high-order blocks exist. */
void video_reserve_backbuffer(void);
/* Enter VESA GUI (1024x768 preferred). Returns 0 on success. */
int video_init_gui(void);
void video_shutdown_gui(void); /* restore text mode 3; keep reserved pool */
int video_ui_scale(void);

void video_clear(uint32_t color);
void video_put_pixel(int x, int y, uint32_t color);
/* Alpha-blend a single pixel onto the backbuffer (GUI builds). */
void video_blend_pixel(int x, int y, uint32_t color, uint8_t alpha);
void video_fill_rect(int x, int y, int w, int h, uint32_t color);
void video_blend_rect(int x, int y, int w, int h, uint32_t color, uint8_t alpha);
void video_draw_rect(int x, int y, int w, int h, uint32_t color);
void video_fill_round_rect(int x, int y, int w, int h, int r, uint32_t color);
void video_blend_round_rect(int x, int y, int w, int h, int r, uint32_t color,
                            uint8_t alpha);
void video_gradient_v(int x, int y, int w, int h, uint32_t c0, uint32_t c1);
void video_gradient_h(int x, int y, int w, int h, uint32_t c0, uint32_t c1);
/* Bilinear corner gradient (tl/tr/bl/br) — for desktop wallpaper. */
/* Second half of the reserved VESA pool may hold a wallpaper snapshot. */
uint8_t *video_wallpaper_slot(uint32_t frame_bytes);
void video_shadow_rect(int x, int y, int w, int h, int radius, int depth);
void video_fill_circle(int cx, int cy, int r, uint32_t color);
void video_draw_char(int x, int y, char c, uint32_t fg, uint32_t bg);
void video_draw_char_scaled(int x, int y, char c, uint32_t fg, uint32_t bg,
                            int scale);
void video_draw_string(int x, int y, const char *s, uint32_t fg, uint32_t bg);
void video_draw_string_clip(int x, int y, const char *s, uint32_t fg,
                            uint32_t bg, int clip_x_end);
void video_draw_string_scaled(int x, int y, const char *s, uint32_t fg,
                              uint32_t bg, int scale);
/* UI text: 2x glyphs (16px tall) — much less “DOS” than 8x8. */
void video_draw_ui(int x, int y, const char *s, uint32_t fg);
void video_draw_ui_clip(int x, int y, const char *s, uint32_t fg, int clip_x_end);
int video_ui_width(const char *s);
void video_present(void);
#else
static inline void video_reserve_backbuffer(void) {}
static inline int video_init_gui(void) { return -1; }
static inline void video_shutdown_gui(void) {}
static inline void video_present(void) {}
static inline int video_ui_scale(void) { return 2; }
static inline uint8_t *video_wallpaper_slot(uint32_t frame_bytes) {
  (void)frame_bytes;
  return 0;
}
#endif

#endif
