#include "keyboard.h"
#include "net.h"
#include "ssh.h"
#include <stddef.h>
#include <stdint.h>

extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern size_t kstrlen(const char *s);
extern void background_logs_set(int disabled);
extern void terminal_clear(void);
extern void terminal_putchar(char c);
extern int input_getkey(void);
extern void ssh_shell_log_flush(void);
extern int fat12_read_file_to_ram(const char *path, uint8_t **out_buf,
                                  uint32_t *out_size);
extern int fat12_write_file(const char *fn, const uint8_t *data, uint32_t size);
extern void kfree(void *ptr);
extern void *kmalloc(size_t size);
extern int file_slot_save(const char *name, const uint8_t *data, uint32_t size);
extern int file_slot_read(const char *name, uint8_t **out_buf,
                          uint32_t *out_size);
extern const char *skip_spaces(const char *s);

extern size_t terminal_row;
extern size_t terminal_column;
extern uint8_t terminal_color;
extern void terminal_update_hw_cursor(void);

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define ED_MAX_ROWS 100
#define ED_MAX_COLS 80

static char ed_buffer[ED_MAX_ROWS][ED_MAX_COLS + 1];
static int ed_rows = 0;

static int cx = 0;
static int cy = 0;
static int scroll_y = 0;

static char filename[32];
static int is_dirty = 0;
static uint32_t last_k = 0;

static const char *ed_status_msg = 0;

#define COL_TEXT 0x07
#define COL_BAR 0x70

/* Local VGA only when not serving an SSH remote shell command. */
static int ed_use_vga(void)
{
#ifndef AJOS_SERIAL_ONLY
  return !ssh_shell_log_sink_active();
#else
  return 0;
#endif
}

/* Always available: serial ANSI UI (Terminal / -serial stdio / SSH). */
static void serial_print_ansi(const char *cmd) { log_writestring(cmd); }

static void serial_set_cursor(int r, int c)
{
  log_putchar('\x1b');
  log_putchar('[');
  log_write_u32((uint32_t)(r + 1));
  log_putchar(';');
  log_write_u32((uint32_t)(c + 1));
  log_putchar('H');
}

static void serial_colors_bar(int is_bar)
{
  if (is_bar)
    serial_print_ansi("\x1b[30;47m");
  else
    serial_print_ansi("\x1b[37;40m");
}

static void ed_draw_bar(int row, const char *text, uint8_t color)
{
  (void)color;
  serial_set_cursor(row, 0);
  serial_colors_bar(1);
  if (ed_use_vga())
  {
    for (int i = 0; i < VGA_WIDTH; i++)
      log_putchar(' ');
    serial_set_cursor(row, 0);
  }
  else
  {
    /* SSH/serial: clear line once instead of 80 spaces (avoids TX stalls). */
    serial_print_ansi("\x1b[2K");
  }
  log_writestring(text);
  serial_print_ansi("\x1b[0m");

  if (ed_use_vga())
  {
    uint8_t *vid = (uint8_t *)0xB8000;
    for (int i = 0; i < VGA_WIDTH; i++)
    {
      vid[(row * VGA_WIDTH + i) * 2] = ' ';
      vid[(row * VGA_WIDTH + i) * 2 + 1] = COL_BAR;
    }
    int i = 0;
    while (text[i] && i < VGA_WIDTH)
    {
      vid[(row * VGA_WIDTH + i) * 2] = text[i];
      vid[(row * VGA_WIDTH + i) * 2 + 1] = COL_BAR;
      i++;
    }
  }
}

static void ed_render(void)
{
  char title[80];
  char *t = title;
  const char *p = "AJOS Editor: ";
  while (*p)
    *t++ = *p++;
  p = filename;
  while (*p)
    *t++ = *p++;
  *t = 0;
  ed_draw_bar(0, title, COL_BAR);

  int ssh_ui = !ed_use_vga();
  serial_print_ansi("\x1b[0m\x1b[37;40m");
  for (int y = 1; y < VGA_HEIGHT - 1; y++)
  {
    int buf_row = scroll_y + (y - 1);
    serial_set_cursor(y, 0);
    if (ssh_ui)
      serial_print_ansi("\x1b[2K");
    else
    {
      for (int i = 0; i < VGA_WIDTH; i++)
        log_putchar(' ');
      serial_set_cursor(y, 0);
    }
    if (buf_row < ed_rows)
    {
      for (int x = 0; x < ED_MAX_COLS; x++)
      {
        char c = ed_buffer[buf_row][x];
        if (c == 0)
          break;
        log_putchar(c);
      }
    }
  }

#ifndef AJOS_SERIAL_ONLY
  if (ed_use_vga())
  {
    uint8_t *vid = (uint8_t *)0xB8000;
    for (int y = 1; y < VGA_HEIGHT - 1; y++)
    {
      int buf_row = scroll_y + (y - 1);
      for (int x = 0; x < VGA_WIDTH; x++)
      {
        int idx = (y * VGA_WIDTH + x) * 2;
        char c = ' ';
        if (buf_row < ed_rows)
        {
          char ch = ed_buffer[buf_row][x];
          if (ch)
            c = ch;
        }
        vid[idx] = c;
        vid[idx + 1] = COL_TEXT;
      }
    }
  }
#endif

  if (ed_status_msg)
    ed_draw_bar(VGA_HEIGHT - 1, ed_status_msg, COL_BAR);
  else
    ed_draw_bar(VGA_HEIGHT - 1, "^X Exit   ^O/^S Save   Tab=shell complete",
                COL_BAR);

  if (ed_use_vga())
  {
    terminal_row = (uint8_t)(cy - scroll_y + 1);
    terminal_column = (uint8_t)cx;
    terminal_update_hw_cursor();
  }
  serial_set_cursor((cy - scroll_y) + 1, cx);
}

static void ed_save(void)
{
  uint32_t total_size = 0;
  for (int i = 0; i < ed_rows; i++)
  {
    int len = 0;
    while (len < ED_MAX_COLS && ed_buffer[i][len] != 0)
      len++;
    total_size += (uint32_t)len;
    if (i < ed_rows - 1 || len > 0)
      total_size++;
  }
  if (total_size == 0)
    total_size = 1;

  uint8_t *tmp = (uint8_t *)kmalloc(total_size);
  if (!tmp)
  {
    ed_status_msg = "[ERROR: Out of memory]";
    ed_draw_bar(VGA_HEIGHT - 1, ed_status_msg, COL_BAR);
    return;
  }

  uint32_t p = 0;
  for (int i = 0; i < ed_rows; i++)
  {
    int len = 0;
    while (len < ED_MAX_COLS && ed_buffer[i][len] != 0)
    {
      tmp[p++] = (uint8_t)ed_buffer[i][len];
      len++;
    }
    if (i < ed_rows - 1 || len > 0)
      tmp[p++] = '\n';
  }
  if (p == 0)
  {
    tmp[p++] = '\n';
    total_size = 1;
  }

  int saved_ram = file_slot_save(filename, tmp, p);
  (void)fat12_write_file(filename, tmp, p);
  kfree(tmp);

  if (saved_ram >= 0)
    ed_status_msg = (p <= 1) ? "[Saved (empty file)]" : "Save success";
  else
    ed_status_msg = "[ERROR: Save failed]";
  ed_draw_bar(VGA_HEIGHT - 1, ed_status_msg, COL_BAR);
}

void editor_open(const char *fn)
{
  for (int i = 0; i < ED_MAX_ROWS; i++)
    for (int j = 0; j <= ED_MAX_COLS; j++)
      ed_buffer[i][j] = 0;
  ed_rows = 1;
  cx = 0;
  cy = 0;
  scroll_y = 0;
  is_dirty = 0;
  ed_status_msg = 0;

  fn = skip_spaces(fn ? fn : "");
  int i = 0;
  for (; fn[i] && i < 31; i++)
  {
    if (fn[i] >= 32 && fn[i] < 127)
      filename[i] = fn[i];
    else
      filename[i] = '_';
  }
  filename[i] = 0;

  /* Truncate overlong 8.3 extensions: index.html -> index.htm */
  char *dot = 0;
  for (int j = 0; j < 32 && filename[j]; j++)
  {
    if (filename[j] == '.')
    {
      dot = &filename[j];
      break;
    }
  }
  if (dot && kstrlen(dot) > 4)
    dot[4] = '\0';

  if (i == 0)
  {
    filename[0] = 'N';
    filename[1] = 'E';
    filename[2] = 'W';
    filename[3] = 0;
  }

  uint8_t *fbuf = NULL;
  uint32_t fsize = 0;
  int loaded = 0;

  log_writestring("Editor: loading ");
  log_writestring(filename);
  log_writestring("...\n");
  if (ssh_shell_log_sink_active())
    ssh_shell_log_flush();

  if (file_slot_read(filename, &fbuf, &fsize) == 1)
    loaded = 1;
  else if (fat12_read_file_to_ram(filename, &fbuf, &fsize))
    loaded = 1;

  if (loaded && fbuf != NULL)
  {
    uint32_t addr = (uint32_t)fbuf;
    if (addr < 0x00800000u || addr >= 0x1E000000u)
    {
      log_writestring("Editor: invalid file buffer pointer\n");
      kfree(fbuf);
      fbuf = NULL;
      loaded = 0;
    }
    else if (fsize > 1000000u)
    {
      log_writestring("Editor: file too large\n");
      kfree(fbuf);
      fbuf = NULL;
      loaded = 0;
    }
  }

  if (loaded && fbuf != NULL)
  {
    ed_rows = 0;
    int col = 0;
    int row = 0;
    uint32_t max_size = fsize < 1000000u ? fsize : 1000000u;
    for (uint32_t j = 0; j < max_size; j++)
    {
      char c = (char)fbuf[j];
      if (c == '\r')
        continue;
      if (c == '\n')
      {
        if (row < ED_MAX_ROWS)
        {
          ed_buffer[row][col] = 0;
          row++;
        }
        col = 0;
        if (row >= ED_MAX_ROWS)
          break;
      }
      else if (col < ED_MAX_COLS && row < ED_MAX_ROWS)
      {
        if (c >= 32 && c < 127)
        {
          ed_buffer[row][col] = c;
          col++;
        }
        else if (c == '\t')
        {
          int spaces = 4 - (col % 4);
          for (int s = 0; s < spaces && col < ED_MAX_COLS; s++)
            ed_buffer[row][col++] = ' ';
        }
      }
    }
    if (row < ED_MAX_ROWS)
    {
      ed_buffer[row][col] = 0;
      if (col > 0 || row == 0)
        row++;
    }
    ed_rows = row;
    if (ed_rows == 0)
      ed_rows = 1;
    kfree(fbuf);
    log_writestring("Editor: loaded ");
    log_write_u32((uint32_t)ed_rows);
    log_writestring(" lines from ");
    log_writestring(filename);
    log_putchar('\n');
  }
  else
  {
    ed_buffer[0][0] = 0;
    ed_rows = 1;
    log_writestring("Editor: new/empty file ");
    log_writestring(filename);
    log_putchar('\n');
  }

  log_writestring("Starting Editor...  (Ctrl+X to exit)\n");
  if (ssh_shell_log_sink_active())
    log_writestring("Mode: SSH\n");
#ifdef AJOS_SERIAL_ONLY
  else
    log_writestring("Mode: SERIAL\n");
#else
  else
    log_writestring("Mode: VGA+SERIAL (local console)\n");
#endif
  if (ssh_shell_log_sink_active())
    ssh_shell_log_flush();

  background_logs_set(1);
  if (ed_use_vga())
    terminal_clear();
  serial_print_ansi("\x1b[2J\x1b[H");
  if (ssh_shell_log_sink_active())
    ssh_shell_log_flush();

  while (1)
  {
    ed_render();
    if (ssh_shell_log_sink_active())
      ssh_shell_log_flush();

    int k = input_getkey();
    last_k = (uint32_t)k;
    ed_status_msg = 0;

    if (k == 24)
    { /* Ctrl+X */
      break;
    }

    if (k == 15 || k == 19)
    { /* Ctrl+O / Ctrl+S */
      ed_save();
      continue;
    }

    if (k == KEY_UP)
    {
      if (cy > 0)
        cy--;
      if (cy < scroll_y)
        scroll_y = cy;
      int len = (int)kstrlen(ed_buffer[cy]);
      if (cx > len)
        cx = len;
    }
    else if (k == KEY_DOWN)
    {
      if (cy < ed_rows - 1)
        cy++;
      if (cy >= scroll_y + (VGA_HEIGHT - 2))
        scroll_y = cy - (VGA_HEIGHT - 3);
      int len = (int)kstrlen(ed_buffer[cy]);
      if (cx > len)
        cx = len;
    }
    else if (k == KEY_LEFT)
    {
      if (cx > 0)
        cx--;
      else if (cy > 0)
      {
        cy--;
        cx = (int)kstrlen(ed_buffer[cy]);
      }
    }
    else if (k == KEY_RIGHT)
    {
      int len = (int)kstrlen(ed_buffer[cy]);
      if (cx < len)
        cx++;
      else if (cy < ed_rows - 1)
      {
        cy++;
        cx = 0;
      }
    }
    else if (k == '\n' || k == '\r')
    {
      if (ed_rows < ED_MAX_ROWS)
      {
        for (int r = ed_rows; r > cy + 1; r--)
        {
          for (int j = 0; j <= ED_MAX_COLS; j++)
            ed_buffer[r][j] = ed_buffer[r - 1][j];
        }
        int len = (int)kstrlen(ed_buffer[cy]);
        int next_col = 0;
        for (int j = cx; j < len; j++)
        {
          ed_buffer[cy + 1][next_col++] = ed_buffer[cy][j];
          ed_buffer[cy][j] = 0;
        }
        ed_buffer[cy + 1][next_col] = 0;
        ed_rows++;
        cy++;
        cx = 0;
        is_dirty = 1;
      }
    }
    else if (k == '\b')
    {
      if (cx > 0)
      {
        int len = (int)kstrlen(ed_buffer[cy]);
        for (int j = cx - 1; j < len; j++)
          ed_buffer[cy][j] = ed_buffer[cy][j + 1];
        cx--;
        is_dirty = 1;
      }
      else if (cy > 0)
      {
        int prev_len = (int)kstrlen(ed_buffer[cy - 1]);
        int cur_len = (int)kstrlen(ed_buffer[cy]);
        if (prev_len + cur_len < ED_MAX_COLS)
        {
          for (int j = 0; j < cur_len; j++)
            ed_buffer[cy - 1][prev_len + j] = ed_buffer[cy][j];
          ed_buffer[cy - 1][prev_len + cur_len] = 0;
          for (int r = cy; r < ed_rows - 1; r++)
          {
            for (int j = 0; j <= ED_MAX_COLS; j++)
              ed_buffer[r][j] = ed_buffer[r + 1][j];
          }
          ed_rows--;
          cy--;
          cx = prev_len;
          is_dirty = 1;
        }
      }
    }
    else if (k >= 32 && k <= 126)
    {
      if ((int)kstrlen(ed_buffer[cy]) < ED_MAX_COLS)
      {
        int len = (int)kstrlen(ed_buffer[cy]);
        for (int j = len; j >= cx; j--)
          ed_buffer[cy][j + 1] = ed_buffer[cy][j];
        ed_buffer[cy][cx] = (char)k;
        cx++;
        is_dirty = 1;
      }
    }
  }

  (void)is_dirty;
  (void)last_k;
  background_logs_set(0);
  terminal_clear();
  serial_print_ansi("\x1b[2J\x1b[H");
}
