#include "gui.h"
#include "fat.h"
#include "io.h"
#include "kernel.h"
#include "keyboard.h"
#include "mouse.h"
#include "video.h"
#include <stddef.h>
#include <stdint.h>

#ifndef AJOS_SERIAL_ONLY

extern void shell_execute(const char *line);
extern int input_getchar_noblock(void);
extern void netdev_napi_poll(int budget);
extern volatile uint32_t pit_ticks;
extern void shell_gui_sink_begin(char *buf, size_t cap);
extern size_t shell_gui_sink_end(void);
void kfree(void *ptr);
extern void log_writestring(const char *s);

#define PANEL_H 32
#define TITLE_H 40
#define MAX_WINS 4
#define TERM_OUT_CAP 8192
#define TERM_LINE_CAP 160
#define FILES_CAP 4096
#define UI_CH (8 * video_ui_scale())
#define DOCK_N 3
#define DOCK_ICON 56
#define DOCK_GAP 18
#define DOCK_PAD 10
#define DOCK_H (DOCK_ICON + 2 * DOCK_PAD + 8)

typedef struct GuiWindow GuiWindow;
struct GuiWindow {
  int x, y, w, h;
  const char *title;
  int visible;
  int focused;
  int anim;
  void (*on_draw)(GuiWindow *win);
  void (*on_key)(GuiWindow *win, int key);
};

static GuiWindow wins[MAX_WINS];
static int win_order[MAX_WINS];
static int n_wins;
static int running;
static int drag_win = -1;
static int drag_ox, drag_oy;
static int dock_pressed = -1;
static uint32_t dock_press_until;

static char term_out[TERM_OUT_CAP];
static size_t term_out_len;
static char term_line[TERM_LINE_CAP];
static size_t term_line_len;
static int term_scroll;

static char files_buf[FILES_CAP];
static int files_scroll;

static void term_out_append(const char *s) {
  if (!s)
    return;
  while (*s && term_out_len + 1 < TERM_OUT_CAP)
    term_out[term_out_len++] = *s++;
  term_out[term_out_len] = '\0';
}

static void term_out_append_char(char c) {
  if (term_out_len + 1 < TERM_OUT_CAP) {
    term_out[term_out_len++] = c;
    term_out[term_out_len] = '\0';
  }
}

static int count_lines(const char *s, size_t len) {
  int lines = 1;
  if (!len)
    return 0;
  for (size_t i = 0; i < len; i++)
    if (s[i] == '\n')
      lines++;
  return lines;
}

static const char *line_at(const char *s, size_t len, int idx, size_t *out_len) {
  int cur = 0;
  size_t start = 0;
  for (size_t i = 0; i <= len; i++) {
    if (i == len || s[i] == '\n') {
      if (cur == idx) {
        *out_len = i - start;
        return s + start;
      }
      cur++;
      start = i + 1;
    }
  }
  *out_len = 0;
  return s;
}

static void format_clock(char *out, size_t cap) {
  uint32_t sec = pit_ticks / 100u;
  uint32_t h = (sec / 3600u) % 24u;
  uint32_t m = (sec / 60u) % 60u;
  if (cap < 6)
    return;
  out[0] = (char)('0' + (h / 10));
  out[1] = (char)('0' + (h % 10));
  out[2] = ':';
  out[3] = (char)('0' + (m / 10));
  out[4] = (char)('0' + (m % 10));
  out[5] = '\0';
}

static uint8_t *wall_cache = 0;
static int wall_ready = 0;

static void draw_wallpaper(void) {
  uint32_t sz = (uint32_t)video_width * (uint32_t)video_height * 4u;
  if (!wall_ready) {
    /* Light macOS-style sweep: soft blue to near-white, warm glow low */
    video_gradient_v(0, 0, video_width, video_height, COL_BG_TL, COL_BG_BR);
    video_blend_round_rect(video_width / 4, video_height / 2, video_width / 2,
                            video_height / 2, 160, COL_SURFACE, 38);
    video_blend_round_rect(video_width / 3, video_height / 6, video_width / 3,
                            video_height / 3, 120, vid_rgb(120, 170, 255), 26);
    wall_cache = video_wallpaper_slot(sz);
    if (wall_cache && video_back) {
      uint32_t *d = (uint32_t *)wall_cache;
      uint32_t *s = (uint32_t *)video_back;
      uint32_t n = sz / 4u;
      for (uint32_t i = 0; i < n; i++)
        d[i] = s[i];
    }
    wall_ready = 1;
    return;
  }
  if (wall_cache && video_back) {
    uint32_t *d = (uint32_t *)video_back;
    uint32_t *s = (uint32_t *)wall_cache;
    uint32_t n = sz / 4u;
    for (uint32_t i = 0; i < n; i++)
      d[i] = s[i];
    return;
  }
  video_gradient_v(0, 0, video_width, video_height, COL_BG_TL, COL_BG_BR);
}

static void draw_top_panel(void) {
  video_blend_rect(0, 0, video_width, PANEL_H, COL_MENUBAR, 220);
  video_fill_rect(0, PANEL_H - 1, video_width, 1, COL_EDGE);
  video_draw_ui(16, (PANEL_H - UI_CH) / 2, "Activities", COL_TEXT);
  video_draw_ui(16 + video_ui_width("Activities") + 24, (PANEL_H - UI_CH) / 2,
                "AJOS", COL_ORANGE);

  char clk[8];
  format_clock(clk, sizeof(clk));
  int cw = video_ui_width(clk);
  video_draw_ui((video_width - cw) / 2, (PANEL_H - UI_CH) / 2, clk, COL_TEXT);

  /* System tray dots */
  int tx = video_width - 72;
  video_fill_circle(tx, PANEL_H / 2, 3, COL_TEXT_DIM);
  video_fill_circle(tx + 16, PANEL_H / 2, 3, COL_TEXT_DIM);
  video_fill_circle(tx + 32, PANEL_H / 2, 3, COL_ORANGE);
}

static void draw_prompt_glyph(int x, int y, int s, uint32_t fg) {
  int pad = s / 5;
  video_fill_rect(x + pad, y + s / 2 - 2, s / 5, 3, fg);
  video_fill_rect(x + pad + s / 5 - 2, y + s / 2 - 2, 3, s / 5 + 2, fg);
  video_fill_rect(x + pad + s / 3 + 4, y + s / 2 + s / 8, s / 4, 3, fg);
}

static void draw_folder_glyph(int x, int y, int s, uint32_t fg) {
  /* Two-tone folder: darker back flap, lighter front, gloss line. */
  int pad = s / 5;
  int fw = s - pad * 2;
  int fh = s / 2;
  int fy = y + s / 2 - fh / 3;
  video_fill_round_rect(x + pad, fy, fw / 2, fh / 3, 3, fg);
  video_fill_round_rect(x + pad, fy + fh / 5, fw, fh, 5, fg);
  /* Gloss: light band across the front top third. */
  video_blend_round_rect(x + pad + 2, fy + fh / 5 + 2, fw - 4, fh / 3, 4,
                         COL_TEXT_INV, 55);
}

static void draw_info_glyph(int x, int y, int s, uint32_t fg) {
  video_fill_circle(x + s / 2, y + s / 2, s / 3, fg);
  video_draw_ui(x + s / 2 - 4, y + s / 2 - UI_CH / 2, "i", COL_TEXT_INV);
}

typedef struct {
  const char *label;
  int win_idx; /* -1 = quit */
  uint32_t color;
} DockItem;

static DockItem dock_items[DOCK_N] = {
    {"Terminal", 0, 0},
    {"Files", 1, 0},
    {"About", 2, 0},
};

static void dock_item_colors(void) {
  dock_items[0].color = vid_rgb(38, 40, 46);   /* Terminal: near-black */
  dock_items[1].color = vid_rgb(64, 156, 255); /* Files: folder blue */
  dock_items[2].color = vid_rgb(232, 234, 240);/* About: light gray */
}

/* macOS-style bottom dock: icons in a row, centered. */
static int dock_bar_geom(int *bx, int *by, int *bw, int *bh) {
  *bw = DOCK_N * DOCK_ICON + (DOCK_N - 1) * DOCK_GAP + 2 * DOCK_PAD;
  *bh = DOCK_H;
  *bx = (video_width - *bw) / 2;
  *by = video_height - *bh;
  return 1;
}

static void dock_icon_geom(int kind, int *ox, int *oy, int *ow, int *oh) {
  int bx, by, bw, bh;
  dock_bar_geom(&bx, &by, &bw, &bh);
  *ow = DOCK_ICON;
  *oh = DOCK_ICON;
  *ox = bx + DOCK_PAD + kind * (DOCK_ICON + DOCK_GAP);
  *oy = by + (bh - DOCK_ICON) / 2;
}

static void draw_left_dock(int hover) {
  int bx, by, bw, bh;
  dock_bar_geom(&bx, &by, &bw, &bh);
  /* Translucent light shelf with rounded top corners */
  video_blend_round_rect(bx, by, bw, bh, 18, COL_DOCK, 205);
  video_draw_rect(bx, by, bw, bh, COL_EDGE);

  for (int i = 0; i < DOCK_N; i++) {
    int x, y, w, h;
    dock_icon_geom(i, &x, &y, &w, &h);
    int active = (i == hover) || (i == dock_pressed) ||
                 (dock_items[i].win_idx >= 0 &&
                  dock_items[i].win_idx < n_wins &&
                  wins[dock_items[i].win_idx].visible);
    int lift = (i == hover) ? -5 : 0;
    y += lift;

    /* Icon tile: flat squircle with a soft top sheen and hairline */
    video_fill_round_rect(x, y, w, h, 14, dock_items[i].color);
    video_blend_round_rect(x, y, w, h / 2 - 2, 14, COL_TEXT_INV, 26);
    video_draw_rect(x, y, w, h, vid_rgb(255, 255, 255));

    if (i == 0)
      draw_prompt_glyph(x, y, w, COL_TEXT_INV);
    else if (i == 1)
      draw_folder_glyph(x, y, w, vid_rgb(250, 208, 118));
    else
      draw_info_glyph(x, y, w, COL_ORANGE);

    /* Running indicator: small dot under the icon (macOS) */
    if (active)
      video_fill_circle(x + w / 2, by + bh - 4, 3, COL_TEXT_DIM);
  }
}

static int dock_hit(int mx, int my) {
  int bx, by, bw, bh;
  dock_bar_geom(&bx, &by, &bw, &bh);
  if (my < by || my >= video_height || mx < bx || mx >= bx + bw)
    return -1;
  for (int i = 0; i < DOCK_N; i++) {
    int x, y, w, h;
    dock_icon_geom(i, &x, &y, &w, &h);
    y -= 6; /* allow the hover-lift */
    if (mx >= x - 4 && mx < x + w + 4 && my >= y && my < y + h + 6)
      return i;
  }
  return -1;
}

static void draw_window_chrome(GuiWindow *win) {
  int ox = win->x;
  int oy = win->y;
  if (win->anim > 0)
    oy += win->anim * 3;

  video_shadow_rect(ox, oy, win->w, win->h, 12, 5);
  video_fill_round_rect(ox, oy, win->w, win->h, 12, COL_SURFACE);
  video_draw_rect(ox, oy, win->w, win->h, COL_EDGE);

  /* Unified light toolbar */
  video_fill_round_rect(ox + 1, oy + 1, win->w - 2, TITLE_H - 2, 10, COL_TITLE);
  video_fill_rect(ox + 1, oy + TITLE_H - 8, win->w - 2, 8, COL_TITLE);
  video_fill_rect(ox + 12, oy + TITLE_H, win->w - 24, 1, COL_EDGE);

  int cy = oy + TITLE_H / 2;
  /* Traffic lights on the LEFT (macOS): close, minimize, zoom */
  video_fill_circle(ox + 22, cy, 7, COL_CLOSE);
  video_fill_circle(ox + 46, cy, 7, COL_MIN);
  video_fill_circle(ox + 70, cy, 7, COL_MAX);

  int tw = video_ui_width(win->title);
  int tx = ox + (win->w - tw) / 2;
  if (tx < ox + 90)
    tx = ox + 90;
  if (tx + tw > ox + win->w - 16)
    tx = ox + win->w - 16 - tw;
  video_draw_ui(tx, oy + (TITLE_H - UI_CH) / 2, win->title, COL_TEXT);
}

static void about_draw(GuiWindow *win) {
  draw_window_chrome(win);
  int tx = win->x + 32;
  int ty = win->y + TITLE_H + 28;
  int clip = win->x + win->w - 24;
  video_draw_ui(tx, ty, "AJOS", COL_ORANGE);
  video_draw_ui_clip(tx, ty + 36, "Ubuntu-inspired desktop shell.", COL_TEXT,
                     clip);
  video_draw_ui_clip(tx, ty + 60, "Left dock launches apps. Esc exits.",
                     COL_TEXT_DIM, clip);
  video_fill_round_rect(tx, ty + 96, 180, 5, 3, COL_ORANGE);
}

static void files_refresh(void) {
  files_buf[0] = '\0';
  size_t pos = 0;
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  fat12_ctx ctx;
  if (!fat12_init(&ctx)) {
    const char *m = "(fat init failed)";
    while (*m && pos + 1 < FILES_CAP)
      files_buf[pos++] = *m++;
    files_buf[pos] = '\0';
    return;
  }
  int ok = (fat12_cwd_cluster == 0)
               ? fat12_read_root_dir(&ctx, &buf, &bytes)
               : fat12_read_dir_cluster(&ctx, fat12_cwd_cluster, &buf, &bytes);
  if (!ok) {
    fat12_deinit(&ctx);
    const char *m = "(read dir failed)";
    while (*m && pos + 1 < FILES_CAP)
      files_buf[pos++] = *m++;
    files_buf[pos] = '\0';
    return;
  }
  uint32_t entries = bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    char name[13];
    fat12_format_name(e->name, name);
    size_t ni = 0;
    while (name[ni] && pos + 1 < FILES_CAP)
      files_buf[pos++] = name[ni++];
    if (e->attr & 0x10) {
      const char *d = "  /";
      while (*d && pos + 1 < FILES_CAP)
        files_buf[pos++] = *d++;
    }
    if (pos + 1 < FILES_CAP)
      files_buf[pos++] = '\n';
  }
  files_buf[pos] = '\0';
  kfree(buf);
  fat12_deinit(&ctx);
  files_scroll = 0;
}

static void files_draw(GuiWindow *win) {
  draw_window_chrome(win);
  int row_h = UI_CH + 8;
  int cx = win->x + 28;
  int cy = win->y + TITLE_H + 20;
  int rows = (win->h - TITLE_H - 36) / row_h;
  if (rows < 1)
    rows = 1;
  size_t len = 0;
  while (files_buf[len])
    len++;
  int total = count_lines(files_buf, len);
  if (files_scroll > total - rows)
    files_scroll = total - rows;
  if (files_scroll < 0)
    files_scroll = 0;

  video_fill_round_rect(win->x + 16, win->y + TITLE_H + 12, win->w - 32,
                        win->h - TITLE_H - 28, 10, COL_PANEL);

  for (int r = 0; r < rows; r++) {
    size_t ll = 0;
    const char *ln = line_at(files_buf, len, files_scroll + r, &ll);
    char tmp[40];
    size_t copy = ll;
    if (copy > sizeof(tmp) - 1)
      copy = sizeof(tmp) - 1;
    for (size_t i = 0; i < copy; i++)
      tmp[i] = ln[i];
    tmp[copy] = '\0';
    if (!tmp[0])
      continue;
    int ry = cy + r * row_h;
    /* Row icon: soft tile with folder glyph */
    video_fill_round_rect(cx - 8, ry - 4, 22, 22, 6, COL_PANEL2);
    draw_folder_glyph(cx - 10, ry - 6, 26, vid_rgb(64, 156, 255));
    video_draw_ui_clip(cx + 28, ry, tmp, COL_TEXT, win->x + win->w - 28);
  }
}

static void files_key(GuiWindow *win, int key) {
  (void)win;
  if (key == KEY_UP || key == 'k')
    files_scroll--;
  else if (key == KEY_DOWN || key == 'j')
    files_scroll++;
  else if (key == 'r' || key == 'R')
    files_refresh();
}

static void term_run_line(void) {
  if (term_line_len == 0)
    return;
  term_out_append("> ");
  term_out_append(term_line);
  term_out_append_char('\n');

  char capture[TERM_OUT_CAP];
  shell_gui_sink_begin(capture, sizeof(capture));
  shell_execute(term_line);
  size_t n = shell_gui_sink_end();
  for (size_t i = 0; i < n && term_out_len + 1 < TERM_OUT_CAP; i++)
    term_out[term_out_len++] = capture[i];
  term_out[term_out_len] = '\0';

  term_line_len = 0;
  term_line[0] = '\0';
  int lines = count_lines(term_out, term_out_len);
  int rows = 14;
  term_scroll = lines - rows;
  if (term_scroll < 0)
    term_scroll = 0;
}

static void term_draw(GuiWindow *win) {
  draw_window_chrome(win);
  int row_h = UI_CH + 6;
  int cx = win->x + 24;
  int cy = win->y + TITLE_H + 20;
  int body_h = win->h - TITLE_H - 56;
  int rows = body_h / row_h;
  if (rows < 1)
    rows = 1;

  size_t len = term_out_len;
  int total = count_lines(term_out, len);
  if (term_scroll > total - rows)
    term_scroll = total - rows;
  if (term_scroll < 0)
    term_scroll = 0;

  video_fill_round_rect(win->x + 16, win->y + TITLE_H + 12, win->w - 32,
                        body_h + 8, 10, COL_TERM_BG);

  for (int r = 0; r < rows; r++) {
    size_t ll = 0;
    const char *ln = line_at(term_out, len, term_scroll + r, &ll);
    char tmp[64];
    size_t copy = ll;
    if (copy > sizeof(tmp) - 1)
      copy = sizeof(tmp) - 1;
    for (size_t i = 0; i < copy; i++)
      tmp[i] = ln[i];
    tmp[copy] = '\0';
    video_draw_ui_clip(cx, cy + r * row_h, tmp, COL_TERM_FG,
                       win->x + win->w - 28);
  }

  int py = win->y + win->h - 40;
  video_fill_round_rect(win->x + 16, py - 6, win->w - 32, 34, 10,
                        vid_rgb(240, 242, 246));
  video_draw_rect(win->x + 16, py - 6, win->w - 32, 34, COL_EDGE);
  video_draw_ui(cx, py, ">", COL_ORANGE);
  char prompt[80];
  size_t copy = term_line_len;
  if (copy > sizeof(prompt) - 1)
    copy = sizeof(prompt) - 1;
  for (size_t i = 0; i < copy; i++)
    prompt[i] = term_line[i];
  prompt[copy] = '\0';
  video_draw_ui_clip(cx + UI_CH + 4, py, prompt, COL_TERM_FG,
                     win->x + win->w - 28);
  if (((pit_ticks / 35) & 1) == 0) {
    int caretx = cx + UI_CH + 4 + (int)copy * UI_CH;
    video_fill_rect(caretx, py + 2, 10, UI_CH - 2, COL_ORANGE);
  }
}

static void term_key(GuiWindow *win, int key) {
  (void)win;
  if (key == '\n' || key == '\r') {
    term_run_line();
    return;
  }
  if (key == '\b' || key == 127) {
    if (term_line_len > 0)
      term_line[--term_line_len] = '\0';
    return;
  }
  if (key == KEY_UP)
    term_scroll--;
  else if (key == KEY_DOWN)
    term_scroll++;
  else if (key >= 32 && key < 127) {
    if (term_line_len + 1 < TERM_LINE_CAP) {
      term_line[term_line_len++] = (char)key;
      term_line[term_line_len] = '\0';
    }
  }
}

static void bring_to_front(int idx) {
  int pos = -1;
  for (int i = 0; i < n_wins; i++) {
    if (win_order[i] == idx) {
      pos = i;
      break;
    }
  }
  if (pos < 0)
    return;
  for (int i = pos; i < n_wins - 1; i++)
    win_order[i] = win_order[i + 1];
  win_order[n_wins - 1] = idx;
  for (int i = 0; i < n_wins; i++)
    wins[i].focused = 0;
  wins[idx].focused = 1;
}

static void show_window(int idx) {
  if (idx < 0 || idx >= n_wins)
    return;
  wins[idx].visible = 1;
  wins[idx].anim = 5;
  bring_to_front(idx);
}

static void hide_window(int idx) {
  if (idx < 0 || idx >= n_wins)
    return;
  wins[idx].visible = 0;
  wins[idx].focused = 0;
}

static int hit_window(int x, int y) {
  for (int zi = n_wins - 1; zi >= 0; zi--) {
    int i = win_order[zi];
    GuiWindow *w = &wins[i];
    if (!w->visible)
      continue;
    if (x >= w->x && x < w->x + w->w && y >= w->y && y < w->y + w->h)
      return i;
  }
  return -1;
}

typedef struct {
  const char *label;
  int win_idx;
} LauncherItem;

/* Kept for compatibility with older launch path — dock_items is canonical. */
static LauncherItem launch_items[DOCK_N];

static void draw_cursor(int x, int y) {
  static const char *rows[] = {
      "X        ", "XX       ", "X.X      ", "X..X     ", "X...X    ",
      "X....X   ", "X.....X  ", "X......X ", "X...XXXX ", "X..X     ",
      "X.X      ", "XX       ", "X        "};
  for (int r = 0; r < 13; r++) {
    for (int c = 0; rows[r][c]; c++) {
      if (rows[r][c] == 'X')
        video_put_pixel(x + c, y + r, COL_CURSOR);
      else if (rows[r][c] == '.')
        video_put_pixel(x + c, y + r, COL_BLACK);
    }
  }
}

static void desktop_draw_all(const mouse_state_t *m) {
  draw_wallpaper();
  draw_top_panel();
  draw_left_dock(dock_hit(m->x, m->y));

  for (int zi = 0; zi < n_wins; zi++) {
    int i = win_order[zi];
    if (!wins[i].visible)
      continue;
    if (wins[i].on_draw)
      wins[i].on_draw(&wins[i]);
    if (wins[i].anim > 0)
      wins[i].anim--;
  }

  draw_cursor(m->x, m->y);
  video_present();
}

static void handle_launch(int slot) {
  if (slot < 0 || slot >= DOCK_N)
    return;
  dock_pressed = slot;
  dock_press_until = pit_ticks + 12;
  int wi = dock_items[slot].win_idx;
  if (wi < 0)
    return;
  show_window(wi);
  if (wi == 1) {
    if (!files_buf[0]) {
      const char *m = "Loading...";
      size_t i = 0;
      while (m[i] && i + 1 < FILES_CAP)
        files_buf[i++] = m[i];
      files_buf[i] = '\0';
    }
    files_refresh();
  }
}

static void handle_click(int x, int y) {
  int slot = dock_hit(x, y);
  if (slot >= 0) {
    handle_launch(slot);
    return;
  }
  if (y < PANEL_H)
    return;
  int idx = hit_window(x, y);
  if (idx < 0)
    return;
  GuiWindow *w = &wins[idx];
  bring_to_front(idx);
  int lx = x - w->x;
  int ly = y - w->y;
  /* Close is the leftmost traffic light (macOS layout, at +22) */
  if (ly < TITLE_H && lx >= 12 && lx <= 32) {
    hide_window(idx);
    return;
  }
  if (ly < TITLE_H) {
    drag_win = idx;
    drag_ox = lx;
    drag_oy = ly;
  }
}

void desktop_run(void) {
  if (video_init_gui() != 0) {
    log_writestring("gui: VESA mode failed (need VBE LFB)\n");
    return;
  }

  dock_item_colors();
  for (int i = 0; i < DOCK_N; i++) {
    launch_items[i].label = dock_items[i].label;
    launch_items[i].win_idx = dock_items[i].win_idx;
  }

  n_wins = 0;
  running = 1;
  drag_win = -1;
  dock_pressed = -1;
  wall_cache = 0;
  wall_ready = 0;
  term_out_len = 0;
  term_out[0] = '\0';
  term_line_len = 0;
  term_line[0] = '\0';
  term_scroll = 0;
  files_buf[0] = '\0';
  files_scroll = 0;

  int left = 24;
  int top = PANEL_H + 24;
  wins[n_wins].x = left + 20;
  wins[n_wins].y = top + 20;
  wins[n_wins].w = video_width - left - 48;
  if (wins[n_wins].w > 720)
    wins[n_wins].w = 720;
  wins[n_wins].h = video_height - top - 48;
  if (wins[n_wins].h > 480)
    wins[n_wins].h = 480;
  wins[n_wins].title = "Terminal";
  wins[n_wins].visible = 0;
  wins[n_wins].focused = 0;
  wins[n_wins].anim = 0;
  wins[n_wins].on_draw = term_draw;
  wins[n_wins].on_key = term_key;
  win_order[n_wins] = n_wins;
  n_wins++;

  wins[n_wins].x = left + 60;
  wins[n_wins].y = top + 48;
  wins[n_wins].w = 560;
  wins[n_wins].h = 420;
  wins[n_wins].title = "Files";
  wins[n_wins].visible = 0;
  wins[n_wins].focused = 0;
  wins[n_wins].anim = 0;
  wins[n_wins].on_draw = files_draw;
  wins[n_wins].on_key = files_key;
  win_order[n_wins] = n_wins;
  n_wins++;

  wins[n_wins].x = left + 100;
  wins[n_wins].y = top + 80;
  wins[n_wins].w = 480;
  wins[n_wins].h = 260;
  wins[n_wins].title = "About AJOS";
  wins[n_wins].visible = 0;
  wins[n_wins].focused = 0;
  wins[n_wins].anim = 0;
  wins[n_wins].on_draw = about_draw;
  wins[n_wins].on_key = 0;
  win_order[n_wins] = n_wins;
  n_wins++;

  term_out_append("Welcome to AJOS.\nType help and press Enter.\n");

  mouse_init();

  mouse_state_t prev, cur;
  mouse_poll(&prev);
  prev.buttons = 0;

  while (running) {
    mouse_poll(&cur);

    if (pit_ticks >= dock_press_until)
      dock_pressed = -1;

    if (drag_win >= 0 && mouse_left_pressed(&cur)) {
      wins[drag_win].x = cur.x - drag_ox;
      wins[drag_win].y = cur.y - drag_oy;
      if (wins[drag_win].x < 0)
        wins[drag_win].x = 0;
      if (wins[drag_win].y < PANEL_H)
        wins[drag_win].y = PANEL_H;
      int maxy = video_height - DOCK_H - 40;
      if (wins[drag_win].y > maxy)
        wins[drag_win].y = maxy;
    } else {
      drag_win = -1;
    }

    if (mouse_left_clicked(&cur, &prev)) {
      int cx, cy;
      mouse_click_coords(&cx, &cy);
      handle_click(cx, cy);
    }
    prev = cur;

    int key = input_getchar_noblock();
    if (key != -1) {
      if (key == 27) {
        running = 0;
        break;
      }
      for (int i = 0; i < n_wins; i++) {
        if (wins[i].focused && wins[i].visible && wins[i].on_key) {
          wins[i].on_key(&wins[i], key);
          break;
        }
      }
    }

    netdev_napi_poll(4);

    /* Redraw only when something actually changed: constant reblits make
     * the whole screen shimmer (no vsync on VESA LFB). */
    static int last_mx = -1, last_my = -1, last_btn = -1;
    static int last_caret = -1, last_dock_p = -2, last_min = -1;
    static int any_anim;
    int caret = (pit_ticks / 35) & 1;
    int minute = pit_ticks / 6000u;
    any_anim = 0;
    for (int i = 0; i < n_wins; i++)
      if (wins[i].visible && wins[i].anim > 0)
        any_anim = 1;
    if (cur.x != last_mx || cur.y != last_my ||
        (int)cur.buttons != last_btn || caret != last_caret ||
        dock_pressed != last_dock_p || minute != last_min || any_anim ||
        key != -1) {
      last_mx = cur.x;
      last_my = cur.y;
      last_btn = cur.buttons;
      last_caret = caret;
      last_dock_p = dock_pressed;
      last_min = minute;
      desktop_draw_all(&cur);
    }
  }

  mouse_shutdown();
  video_shutdown_gui();
}

#endif
