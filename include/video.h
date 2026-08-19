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

/* AJOS identity palette: macOS-inspired light theme. Legacy color names
 * (COL_ORANGE etc.) map to the accent so all callers restyle. */
#define COL_BG0 vid_rgb(168, 190, 232)
#define COL_BG1 vid_rgb(226, 235, 248)
#define COL_BG_TL vid_rgb(158, 184, 233)
#define COL_BG_TR vid_rgb(192, 209, 240)
#define COL_BG_BL vid_rgb(214, 226, 245)
#define COL_BG_BR vid_rgb(240, 245, 251)
/* accent (Apple blue; was orange) */
#define COL_ORANGE vid_rgb(0, 122, 255)
#define COL_ORANGE_DIM vid_rgb(0, 90, 190)
/* secondary steel (was aubergine) */
#define COL_AUBERGINE vid_rgb(100, 116, 139)
#define COL_TEAL vid_rgb(0, 122, 255) /* accent reuse for caret/focus */
#define COL_TEAL_DIM vid_rgb(0, 90, 190)
#define COL_ACCENT2 vid_rgb(52, 199, 89)  /* green */
#define COL_PANEL vid_rgb(248, 249, 251)
#define COL_PANEL2 vid_rgb(238, 241, 245)
#define COL_ICON vid_rgb(96, 106, 124)
#define COL_ICON_HI vid_rgb(120, 132, 154)
#define COL_SURFACE vid_rgb(255, 255, 255)
#define COL_EDGE vid_rgb(208, 212, 220)
#define COL_EDGE_HI vid_rgb(0, 122, 255)
#define COL_TEXT vid_rgb(32, 36, 44)
#define COL_TEXT_DIM vid_rgb(128, 136, 150)
#define COL_TEXT_INV vid_rgb(255, 255, 255)
#define COL_TITLE vid_rgb(246, 247, 249)
#define COL_CLOSE vid_rgb(255, 95, 86)
#define COL_MIN vid_rgb(255, 189, 46)
#define COL_MAX vid_rgb(39, 201, 63)
#define COL_TASKBAR vid_rgb(246, 247, 249)
#define COL_TASK_BTN vid_rgb(228, 232, 238)
#define COL_DOCK vid_rgb(244, 246, 250)
#define COL_MENUBAR vid_rgb(250, 251, 253)
#define COL_CURSOR vid_rgb(32, 36, 44)
#define COL_BLACK vid_rgb(0, 0, 0)
#define COL_TERM_BG vid_rgb(252, 252, 253)
#define COL_TERM_FG vid_rgb(30, 34, 42)

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
