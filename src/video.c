#include "video.h"
#include "io.h"
#include "minoca/mm.h"
#include "pmm.h"
#include <stddef.h>

#ifndef AJOS_SERIAL_ONLY

extern uint32_t bios_vbe_set_mode(uint32_t mode);
extern uint32_t bios_vbe_get_mode_info(uint32_t mode, uint32_t dest_phys);
extern void bios_vga_set_mode(uint32_t mode_al);
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);

#define BIOS_STATUS_PHYS 0x8418u
#define VBE_INFO_PHYS 0x8600u
#define VIDEO_BB_MAX_ORDER 10 /* 4 MiB — enough for 1024x768x32 */

int video_width = 1024;
int video_height = 768;
int video_pitch = 1024 * 4;
int video_bpp = 32;
uint8_t *video_fb = 0;
uint8_t *video_back = 0;

/* Reserved before buddy fragmentation; never freed for the GUI lifetime. */
static uint8_t *video_bb_pool = 0;
static int video_bb_order = -1;

static uint8_t *draw_surface(void) {
  return video_back ? video_back : video_fb;
}

static uint32_t video_bb_pool_bytes(void) {
  if (video_bb_order < 0 || !video_bb_pool)
    return 0;
  return PAGE_SIZE << video_bb_order;
}

void video_reserve_backbuffer(void) {
  if (video_bb_pool)
    return;
  /* Prefer 4 MiB so 1024x768 ARGB fits; fall back to 2 MiB (800x600). */
  video_bb_pool = (uint8_t *)pmm_alloc_page(VIDEO_BB_MAX_ORDER);
  if (video_bb_pool) {
    video_bb_order = VIDEO_BB_MAX_ORDER;
  } else {
    video_bb_pool = (uint8_t *)pmm_alloc_page(9);
    if (video_bb_pool)
      video_bb_order = 9;
  }
  if (video_bb_pool) {
    log_writestring("[VESA] reserved backbuffer ");
    log_write_u32(video_bb_pool_bytes() / 1024u);
    log_writestring(" KiB\n");
  } else {
    log_writestring("[VESA] WARNING: no contiguous backbuffer\n");
  }
}

/* 8x8 glyphs ASCII 32..126 — LSB = left. */
static const uint8_t font8x8[95][8] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00},
    {0x36, 0x36, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00},
    {0x0C, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x0C, 0x00},
    {0x00, 0x63, 0x33, 0x18, 0x0C, 0x66, 0x63, 0x00},
    {0x1C, 0x36, 0x1C, 0x6E, 0x3B, 0x33, 0x6E, 0x00},
    {0x06, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x18, 0x0C, 0x06, 0x06, 0x06, 0x0C, 0x18, 0x00},
    {0x06, 0x0C, 0x18, 0x18, 0x18, 0x0C, 0x06, 0x00},
    {0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00},
    {0x00, 0x0C, 0x0C, 0x3F, 0x0C, 0x0C, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x06},
    {0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x00},
    {0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x01, 0x00},
    {0x3E, 0x63, 0x73, 0x7B, 0x6F, 0x67, 0x3E, 0x00},
    {0x0C, 0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x3F, 0x00},
    {0x1E, 0x33, 0x30, 0x1C, 0x06, 0x33, 0x3F, 0x00},
    {0x1E, 0x33, 0x30, 0x1C, 0x30, 0x33, 0x1E, 0x00},
    {0x38, 0x3C, 0x36, 0x33, 0x7F, 0x30, 0x78, 0x00},
    {0x3F, 0x03, 0x1F, 0x30, 0x30, 0x33, 0x1E, 0x00},
    {0x1C, 0x06, 0x03, 0x1F, 0x33, 0x33, 0x1E, 0x00},
    {0x3F, 0x33, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x00},
    {0x1E, 0x33, 0x33, 0x1E, 0x33, 0x33, 0x1E, 0x00},
    {0x1E, 0x33, 0x33, 0x3E, 0x30, 0x18, 0x0E, 0x00},
    {0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x00},
    {0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x06},
    {0x18, 0x0C, 0x06, 0x03, 0x06, 0x0C, 0x18, 0x00},
    {0x00, 0x00, 0x3F, 0x00, 0x00, 0x3F, 0x00, 0x00},
    {0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00},
    {0x1E, 0x33, 0x30, 0x18, 0x0C, 0x00, 0x0C, 0x00},
    {0x3E, 0x63, 0x7B, 0x7B, 0x7B, 0x03, 0x1E, 0x00},
    {0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00},
    {0x3F, 0x66, 0x66, 0x3E, 0x66, 0x66, 0x3F, 0x00},
    {0x3C, 0x66, 0x03, 0x03, 0x03, 0x66, 0x3C, 0x00},
    {0x1F, 0x36, 0x66, 0x66, 0x66, 0x36, 0x1F, 0x00},
    {0x7F, 0x06, 0x06, 0x3E, 0x06, 0x06, 0x7F, 0x00},
    {0x7F, 0x06, 0x06, 0x3E, 0x06, 0x06, 0x06, 0x00},
    {0x3C, 0x66, 0x03, 0x03, 0x73, 0x66, 0x7C, 0x00},
    {0x33, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x33, 0x00},
    {0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00},
    {0x78, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E, 0x00},
    {0x67, 0x66, 0x36, 0x1E, 0x36, 0x66, 0x67, 0x00},
    {0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x7F, 0x00},
    {0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00},
    {0x63, 0x67, 0x6F, 0x7B, 0x73, 0x63, 0x63, 0x00},
    {0x1C, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00},
    {0x3F, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x06, 0x00},
    {0x1E, 0x33, 0x33, 0x33, 0x3B, 0x1E, 0x38, 0x00},
    {0x3F, 0x66, 0x66, 0x3E, 0x36, 0x66, 0x67, 0x00},
    {0x1E, 0x33, 0x07, 0x0E, 0x38, 0x33, 0x1E, 0x00},
    {0x3F, 0x2D, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00},
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3F, 0x00},
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00},
    {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00},
    {0x63, 0x63, 0x36, 0x1C, 0x1C, 0x36, 0x63, 0x00},
    {0x33, 0x33, 0x33, 0x1E, 0x0C, 0x0C, 0x1E, 0x00},
    {0x7F, 0x63, 0x31, 0x18, 0x4C, 0x66, 0x7F, 0x00},
    {0x1E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1E, 0x00},
    {0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00},
    {0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00},
    {0x08, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
    {0x0C, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x1E, 0x30, 0x3E, 0x33, 0x6E, 0x00},
    {0x07, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x3B, 0x00},
    {0x00, 0x00, 0x1E, 0x33, 0x03, 0x33, 0x1E, 0x00},
    {0x38, 0x30, 0x30, 0x3e, 0x33, 0x33, 0x6E, 0x00},
    {0x00, 0x00, 0x1E, 0x33, 0x3f, 0x03, 0x1E, 0x00},
    {0x1C, 0x36, 0x06, 0x0f, 0x06, 0x06, 0x0f, 0x00},
    {0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x1F},
    {0x07, 0x06, 0x36, 0x6E, 0x66, 0x66, 0x67, 0x00},
    {0x0C, 0x00, 0x0E, 0x0C, 0x0C, 0x0C, 0x1E, 0x00},
    {0x30, 0x00, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E},
    {0x07, 0x06, 0x66, 0x36, 0x1E, 0x36, 0x67, 0x00},
    {0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00},
    {0x00, 0x00, 0x33, 0x7F, 0x7F, 0x6B, 0x63, 0x00},
    {0x00, 0x00, 0x1F, 0x33, 0x33, 0x33, 0x33, 0x00},
    {0x00, 0x00, 0x1E, 0x33, 0x33, 0x33, 0x1E, 0x00},
    {0x00, 0x00, 0x3B, 0x66, 0x66, 0x3E, 0x06, 0x0F},
    {0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x78},
    {0x00, 0x00, 0x3B, 0x6E, 0x66, 0x06, 0x0F, 0x00},
    {0x00, 0x00, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x00},
    {0x08, 0x0C, 0x3E, 0x0C, 0x0C, 0x2C, 0x18, 0x00},
    {0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x6E, 0x00},
    {0x00, 0x00, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00},
    {0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00},
    {0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00},
    {0x00, 0x00, 0x33, 0x33, 0x33, 0x3E, 0x30, 0x1F},
    {0x00, 0x00, 0x3F, 0x19, 0x0C, 0x26, 0x3F, 0x00},
    {0x38, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x38, 0x00},
    {0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00},
    {0x07, 0x0C, 0x0C, 0x38, 0x0C, 0x0C, 0x07, 0x00},
    {0x6E, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

static uint16_t bios_last_ax(void) {
  return *(volatile uint16_t *)BIOS_STATUS_PHYS;
}

static int try_vbe_mode(uint16_t mode, int require_32bpp) {
  uint8_t *info = (uint8_t *)VBE_INFO_PHYS;
  for (int i = 0; i < 256; i++)
    info[i] = 0;

  bios_vbe_get_mode_info(mode, VBE_INFO_PHYS);
  if ((bios_last_ax() & 0xFF) != 0x4F)
    return -1;

  uint16_t attr = *(uint16_t *)(info + 0);
  /* D0 supported, D4 graphics. LFB bit (D7) is not always set on QEMU/Bochs
   * even when PhysBasePtr is valid — trust a non-zero LFB address. */
  if (!(attr & 0x01) || !(attr & 0x10))
    return -1;

  uint16_t w = *(uint16_t *)(info + 0x12);
  uint16_t h = *(uint16_t *)(info + 0x14);
  uint8_t bpp = info[0x19];
  uint16_t pitch = *(uint16_t *)(info + 0x10);
  uint32_t lfb = *(uint32_t *)(info + 0x28);
  if (!lfb || w < 640 || h < 480 || (bpp != 32 && bpp != 24 && bpp != 16))
    return -1;
  /* QEMU labels many "32-bit" list entries as 24bpp — skip those when we
   * specifically need a fast 32bpp memcpy present path. */
  if (require_32bpp && bpp != 32)
    return -1;

  uint32_t back_sz = (uint32_t)w * (uint32_t)h * 4u;
  if (!video_bb_pool || back_sz > video_bb_pool_bytes())
    return -2; /* need reserved contiguous ARGB pool */

  bios_vbe_set_mode(mode);
  uint16_t ax = bios_last_ax();
  if ((ax & 0xFF) != 0x4F || ((ax >> 8) & 0xFF) != 0)
    return -1;

  video_width = (int)w;
  video_height = (int)h;
  video_bpp = (int)bpp;
  video_pitch = pitch ? (int)pitch : (int)w * ((bpp + 7) / 8);
  video_fb = (uint8_t *)lfb;
  video_back = video_bb_pool;

  uint32_t fb_size = (uint32_t)video_pitch * (uint32_t)video_height;
  paging_map_framebuffer(lfb, fb_size + 4096u);
  return 0;
}

int video_init_gui(void) {
  if (!video_bb_pool)
    video_reserve_backbuffer();

  /* Pass 0: real 32bpp only. Pass 1: any depth (24bpp convert is slower). */
  static const uint16_t modes[] = {
      0x115, /* 800x600 */
      0x112, /* 640x480 */
      0x118, /* 1024x768 */
      0x117, 0x114, 0x111, 0};
  for (int pass = 0; pass < 2; pass++) {
    for (int i = 0; modes[i]; i++) {
      int r = try_vbe_mode(modes[i], pass == 0);
      if (r == 0) {
        log_writestring("[VESA] mode 0x");
        {
          static const char hex[] = "0123456789abcdef";
          char m[5];
          m[0] = hex[(modes[i] >> 12) & 0xF];
          m[1] = hex[(modes[i] >> 8) & 0xF];
          m[2] = hex[(modes[i] >> 4) & 0xF];
          m[3] = hex[modes[i] & 0xF];
          m[4] = '\0';
          log_writestring(m);
        }
        log_writestring(" ");
        log_write_u32((uint32_t)video_width);
        log_writestring("x");
        log_write_u32((uint32_t)video_height);
        log_writestring("x");
        log_write_u32((uint32_t)video_bpp);
        log_writestring("\n");
        return 0;
      }
      video_back = 0;
      video_fb = 0;
    }
  }
  return -1;
}

void video_shutdown_gui(void) {
  /* Keep video_bb_pool — buddy never coalesces, so re-kmalloc would fail. */
  video_back = 0;
  video_fb = 0;
  bios_vga_set_mode(0x03u);
}

uint8_t *video_wallpaper_slot(uint32_t frame_bytes) {
  if (!video_bb_pool || frame_bytes == 0)
    return 0;
  if (video_bb_pool_bytes() < frame_bytes * 2u)
    return 0;
  /* Backbuffer uses [0, frame_bytes); wallpaper cache uses the next slice. */
  return video_bb_pool + frame_bytes;
}

void video_present(void) {
  if (!video_fb || !video_back)
    return;
  if (video_bpp == 32 && video_pitch == video_width * 4) {
    uint32_t n = (uint32_t)video_width * (uint32_t)video_height;
    uint32_t *d = (uint32_t *)video_fb;
    uint32_t *s = (uint32_t *)video_back;
    for (uint32_t i = 0; i < n; i++)
      d[i] = s[i];
    return;
  }
  /* 24bpp fast path: tight BGR pack (QEMU 0x118). */
  if (video_bpp == 24) {
    for (int y = 0; y < video_height; y++) {
      uint32_t *src = (uint32_t *)(video_back + y * video_width * 4);
      uint8_t *dst = video_fb + y * video_pitch;
      for (int x = 0; x < video_width; x++) {
        uint32_t c = src[x];
        dst[0] = (uint8_t)(c & 0xFF);
        dst[1] = (uint8_t)((c >> 8) & 0xFF);
        dst[2] = (uint8_t)((c >> 16) & 0xFF);
        dst += 3;
      }
    }
    return;
  }
  /* Generic: convert from ARGB8888 backbuffer to LFB. */
  for (int y = 0; y < video_height; y++) {
    uint32_t *src = (uint32_t *)(video_back + y * video_width * 4);
    uint8_t *dst = video_fb + y * video_pitch;
    for (int x = 0; x < video_width; x++) {
      uint32_t c = src[x];
      uint8_t r = (c >> 16) & 0xFF;
      uint8_t g = (c >> 8) & 0xFF;
      uint8_t b = c & 0xFF;
      if (video_bpp == 32) {
        dst[x * 4 + 0] = b;
        dst[x * 4 + 1] = g;
        dst[x * 4 + 2] = r;
        dst[x * 4 + 3] = 0xFF;
      } else { /* 16bpp RGB565 */
        uint16_t p = (uint16_t)(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
        dst[x * 2 + 0] = (uint8_t)(p & 0xFF);
        dst[x * 2 + 1] = (uint8_t)(p >> 8);
      }
    }
  }
}

static void put_raw(int x, int y, uint32_t color) {
  if ((unsigned)x >= (unsigned)video_width ||
      (unsigned)y >= (unsigned)video_height)
    return;
  uint32_t *row =
      (uint32_t *)(draw_surface() + (uint32_t)y * (uint32_t)video_width * 4u);
  row[x] = color;
}

void video_put_pixel(int x, int y, uint32_t color) { put_raw(x, y, color); }

void video_clear(uint32_t color) {
  uint32_t *p = (uint32_t *)draw_surface();
  uint32_t n = (uint32_t)video_width * (uint32_t)video_height;
  for (uint32_t i = 0; i < n; i++)
    p[i] = color;
}

void video_fill_rect(int x, int y, int w, int h, uint32_t color) {
  if (w <= 0 || h <= 0)
    return;
  if (x < 0) {
    w += x;
    x = 0;
  }
  if (y < 0) {
    h += y;
    y = 0;
  }
  if (x + w > video_width)
    w = video_width - x;
  if (y + h > video_height)
    h = video_height - y;
  if (w <= 0 || h <= 0)
    return;
  for (int row = 0; row < h; row++) {
    uint32_t *p =
        (uint32_t *)(draw_surface() +
                     (uint32_t)(y + row) * (uint32_t)video_width * 4u) +
        x;
    for (int col = 0; col < w; col++)
      p[col] = color;
  }
}

static uint32_t blend_px(uint32_t dst, uint32_t src, uint8_t a) {
  if (a >= 255)
    return src;
  if (a == 0)
    return dst;
  uint32_t dr = (dst >> 16) & 0xFF, dg = (dst >> 8) & 0xFF, db = dst & 0xFF;
  uint32_t sr = (src >> 16) & 0xFF, sg = (src >> 8) & 0xFF, sb = src & 0xFF;
  uint32_t ia = 255u - a;
  uint32_t r = (sr * a + dr * ia) / 255u;
  uint32_t g = (sg * a + dg * ia) / 255u;
  uint32_t b = (sb * a + db * ia) / 255u;
  return 0xFF000000u | (r << 16) | (g << 8) | b;
}

void video_blend_rect(int x, int y, int w, int h, uint32_t color,
                      uint8_t alpha) {
  if (w <= 0 || h <= 0)
    return;
  if (x < 0) {
    w += x;
    x = 0;
  }
  if (y < 0) {
    h += y;
    y = 0;
  }
  if (x + w > video_width)
    w = video_width - x;
  if (y + h > video_height)
    h = video_height - y;
  if (w <= 0 || h <= 0)
    return;
  for (int row = 0; row < h; row++) {
    uint32_t *p =
        (uint32_t *)(draw_surface() +
                     (uint32_t)(y + row) * (uint32_t)video_width * 4u) +
        x;
    for (int col = 0; col < w; col++)
      p[col] = blend_px(p[col], color, alpha);
  }
}

void video_draw_rect(int x, int y, int w, int h, uint32_t color) {
  if (w <= 0 || h <= 0)
    return;
  video_fill_rect(x, y, w, 1, color);
  video_fill_rect(x, y + h - 1, w, 1, color);
  video_fill_rect(x, y, 1, h, color);
  video_fill_rect(x + w - 1, y, 1, h, color);
}

static int in_round_corner(int lx, int ly, int w, int h, int r) {
  if (r <= 0)
    return 1;
  /* Outside circle in each corner → reject */
  if (lx < r && ly < r) {
    int dx = r - 1 - lx, dy = r - 1 - ly;
    return dx * dx + dy * dy <= r * r;
  }
  if (lx >= w - r && ly < r) {
    int dx = lx - (w - r), dy = r - 1 - ly;
    return dx * dx + dy * dy <= r * r;
  }
  if (lx < r && ly >= h - r) {
    int dx = r - 1 - lx, dy = ly - (h - r);
    return dx * dx + dy * dy <= r * r;
  }
  if (lx >= w - r && ly >= h - r) {
    int dx = lx - (w - r), dy = ly - (h - r);
    return dx * dx + dy * dy <= r * r;
  }
  return 1;
}

void video_fill_round_rect(int x, int y, int w, int h, int r, uint32_t color) {
  if (w <= 0 || h <= 0)
    return;
  for (int j = 0; j < h; j++)
    for (int i = 0; i < w; i++)
      if (in_round_corner(i, j, w, h, r))
        put_raw(x + i, y + j, color);
}

void video_blend_round_rect(int x, int y, int w, int h, int r, uint32_t color,
                            uint8_t alpha) {
  if (w <= 0 || h <= 0)
    return;
  for (int j = 0; j < h; j++) {
    if ((unsigned)(y + j) >= (unsigned)video_height)
      continue;
    uint32_t *row =
        (uint32_t *)(draw_surface() +
                     (uint32_t)(y + j) * (uint32_t)video_width * 4u);
    for (int i = 0; i < w; i++) {
      if ((unsigned)(x + i) >= (unsigned)video_width)
        continue;
      if (!in_round_corner(i, j, w, h, r))
        continue;
      row[x + i] = blend_px(row[x + i], color, alpha);
    }
  }
}

void video_gradient_v(int x, int y, int w, int h, uint32_t c0, uint32_t c1) {
  if (w <= 0 || h <= 0)
    return;
  uint32_t r0 = (c0 >> 16) & 0xFF, g0 = (c0 >> 8) & 0xFF, b0 = c0 & 0xFF;
  uint32_t r1 = (c1 >> 16) & 0xFF, g1 = (c1 >> 8) & 0xFF, b1 = c1 & 0xFF;
  for (int j = 0; j < h; j++) {
    uint32_t t = (h <= 1) ? 0 : (uint32_t)(j * 255) / (uint32_t)(h - 1);
    uint32_t r = (r0 * (255 - t) + r1 * t) / 255;
    uint32_t g = (g0 * (255 - t) + g1 * t) / 255;
    uint32_t b = (b0 * (255 - t) + b1 * t) / 255;
    video_fill_rect(x, y + j, w, 1, 0xFF000000u | (r << 16) | (g << 8) | b);
  }
}

void video_gradient_h(int x, int y, int w, int h, uint32_t c0, uint32_t c1) {
  if (w <= 0 || h <= 0)
    return;
  uint32_t r0 = (c0 >> 16) & 0xFF, g0 = (c0 >> 8) & 0xFF, b0 = c0 & 0xFF;
  uint32_t r1 = (c1 >> 16) & 0xFF, g1 = (c1 >> 8) & 0xFF, b1 = c1 & 0xFF;
  for (int i = 0; i < w; i++) {
    uint32_t t = (w <= 1) ? 0 : (uint32_t)(i * 255) / (uint32_t)(w - 1);
    uint32_t r = (r0 * (255 - t) + r1 * t) / 255;
    uint32_t g = (g0 * (255 - t) + g1 * t) / 255;
    uint32_t b = (b0 * (255 - t) + b1 * t) / 255;
    video_fill_rect(x + i, y, 1, h, 0xFF000000u | (r << 16) | (g << 8) | b);
  }
}

static uint32_t lerp_chan(uint32_t a, uint32_t b, uint32_t t) {
  return (a * (255u - t) + b * t) / 255u;
}

static uint32_t lerp_rgb(uint32_t c0, uint32_t c1, uint32_t t) {
  uint32_t r = lerp_chan((c0 >> 16) & 0xFF, (c1 >> 16) & 0xFF, t);
  uint32_t g = lerp_chan((c0 >> 8) & 0xFF, (c1 >> 8) & 0xFF, t);
  uint32_t b = lerp_chan(c0 & 0xFF, c1 & 0xFF, t);
  return 0xFF000000u | (r << 16) | (g << 8) | b;
}

void video_gradient_corners(int x, int y, int w, int h, uint32_t tl,
                            uint32_t tr, uint32_t bl, uint32_t br) {
  if (w <= 0 || h <= 0)
    return;
  if (x < 0) {
    w += x;
    x = 0;
  }
  if (y < 0) {
    h += y;
    y = 0;
  }
  if (x + w > video_width)
    w = video_width - x;
  if (y + h > video_height)
    h = video_height - y;
  if (w <= 0 || h <= 0)
    return;
  for (int j = 0; j < h; j++) {
    uint32_t ty = (h <= 1) ? 0 : (uint32_t)(j * 255) / (uint32_t)(h - 1);
    uint32_t L = lerp_rgb(tl, bl, ty);
    uint32_t R = lerp_rgb(tr, br, ty);
    uint32_t *row =
        (uint32_t *)(draw_surface() +
                     (uint32_t)(y + j) * (uint32_t)video_width * 4u) +
        x;
    for (int i = 0; i < w; i++) {
      uint32_t tx = (w <= 1) ? 0 : (uint32_t)(i * 255) / (uint32_t)(w - 1);
      row[i] = lerp_rgb(L, R, tx);
    }
  }
}

void video_fill_circle(int cx, int cy, int r, uint32_t color) {
  if (r <= 0)
    return;
  int r2 = r * r;
  for (int y = -r; y <= r; y++) {
    for (int x = -r; x <= r; x++) {
      if (x * x + y * y <= r2)
        video_put_pixel(cx + x, cy + y, color);
    }
  }
}

void video_shadow_rect(int x, int y, int w, int h, int radius, int depth) {
  if (depth < 1)
    depth = 1;
  for (int i = depth; i >= 1; i--) {
    uint8_t a = (uint8_t)(18 + i * 8);
    video_blend_round_rect(x + i, y + i + 2, w, h, radius, COL_BLACK, a);
  }
}

void video_draw_char_scaled(int x, int y, char c, uint32_t fg, uint32_t bg,
                            int scale) {
  if (scale < 1)
    scale = 1;
  unsigned char uc = (unsigned char)c;
  const uint8_t *glyph =
      (uc < 32 || uc > 126) ? font8x8[0] : font8x8[uc - 32];
  for (int row = 0; row < 8; row++) {
    uint8_t bits = glyph[row];
    for (int col = 0; col < 8; col++) {
      int on = (bits >> col) & 1;
      if (!on && bg == 0)
        continue; /* 0 = transparent for scaled brand */
      uint32_t color = on ? fg : bg;
      if (!on && (bg >> 24) == 0)
        continue;
      video_fill_rect(x + col * scale, y + row * scale, scale, scale, color);
    }
  }
}

void video_draw_char(int x, int y, char c, uint32_t fg, uint32_t bg) {
  unsigned char uc = (unsigned char)c;
  const uint8_t *glyph =
      (uc < 32 || uc > 126) ? font8x8[0] : font8x8[uc - 32];
  for (int row = 0; row < 8; row++) {
    uint8_t bits = glyph[row];
    for (int col = 0; col < 8; col++) {
      int on = (bits >> col) & 1;
      if (!on && bg == 0)
        continue;
      put_raw(x + col, y + row, on ? fg : bg);
    }
  }
}

void video_draw_string_clip(int x, int y, const char *s, uint32_t fg,
                            uint32_t bg, int clip_x_end) {
  if (!s)
    return;
  if (clip_x_end > video_width)
    clip_x_end = video_width;
  int cx = x;
  while (*s) {
    if (*s == '\n') {
      cx = x;
      y += 8;
      s++;
      continue;
    }
    if (cx + 8 > clip_x_end)
      break;
    video_draw_char(cx, y, *s, fg, bg);
    cx += 8;
    s++;
  }
}

void video_draw_string(int x, int y, const char *s, uint32_t fg, uint32_t bg) {
  video_draw_string_clip(x, y, s, fg, bg, video_width);
}

void video_draw_string_scaled(int x, int y, const char *s, uint32_t fg,
                              uint32_t bg, int scale) {
  if (!s)
    return;
  int cx = x;
  while (*s) {
    video_draw_char_scaled(cx, y, *s, fg, bg, scale);
    cx += 8 * scale;
    s++;
  }
}

int video_ui_scale(void) {
  /* 2x glyphs — readable without the chunky 3x DOS look. */
  return 2;
}

void video_draw_ui_clip(int x, int y, const char *s, uint32_t fg,
                        int clip_x_end) {
  if (!s)
    return;
  const int scale = video_ui_scale();
  int cx = x;
  while (*s) {
    if (cx + 8 * scale > clip_x_end)
      break;
    video_draw_char_scaled(cx, y, *s, fg, 0, scale);
    cx += 8 * scale;
    s++;
  }
}

void video_draw_ui(int x, int y, const char *s, uint32_t fg) {
  video_draw_ui_clip(x, y, s, fg, video_width);
}

int video_ui_width(const char *s) {
  int n = 0;
  int adv = 8 * video_ui_scale();
  if (!s)
    return 0;
  while (*s++)
    n += adv;
  return n;
}

#endif /* !AJOS_SERIAL_ONLY */
