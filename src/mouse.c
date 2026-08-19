#include "mouse.h"
#include "io.h"
#include "kernel.h"
#include "video.h"
#include <stddef.h>

#ifndef AJOS_SERIAL_ONLY

#define MOUSE_RING 64
static uint8_t mouse_bytes[MOUSE_RING];
static volatile uint16_t mouse_r;
static volatile uint16_t mouse_w;
static uint8_t packet[3];
static int packet_idx;
static mouse_state_t mouse_cur;
static uint8_t mouse_click_pending;
static int16_t mouse_click_x, mouse_click_y;
static int mouse_accel = 3; /* PS/2 counts → screen pixels */

static void mouse_wait_write(void) {
  uint32_t t = 100000;
  while (t--) {
    if ((inb(0x64) & 2) == 0)
      return;
  }
}

static void mouse_wait_read(void) {
  uint32_t t = 100000;
  while (t--) {
    if (inb(0x64) & 1)
      return;
  }
}

static void mouse_write(uint8_t v) {
  mouse_wait_write();
  outb(0x64, 0xD4);
  mouse_wait_write();
  outb(0x60, v);
}

static uint8_t mouse_read(void) {
  mouse_wait_read();
  return inb(0x60);
}

static void mouse_irq_handler(regs_t *r) {
  (void)r;
  uint8_t b = inb(0x60);
  uint16_t next = (uint16_t)((mouse_w + 1u) % MOUSE_RING);
  if (next != mouse_r) {
    mouse_bytes[mouse_w] = b;
    mouse_w = next;
  }
}

static int screen_w(void) { return video_width > 0 ? video_width : 640; }
static int screen_h(void) { return video_height > 0 ? video_height : 480; }

static void mouse_push_process(uint8_t b) {
  if (packet_idx == 0) {
    if ((b & 0x08) == 0)
      return;
  }
  packet[packet_idx++] = b;
  if (packet_idx < 3)
    return;
  packet_idx = 0;

  int8_t dx = (int8_t)packet[1];
  int8_t dy = (int8_t)packet[2];
  if (packet[0] & 0x40)
    dx = 0;
  if (packet[0] & 0x80)
    dy = 0;

  uint8_t buttons = (uint8_t)(packet[0] & 0x07);
  int adx = (int)dx * mouse_accel;
  int ady = (int)(-dy) * mouse_accel;

  int nx = (int)mouse_cur.x + adx;
  int ny = (int)mouse_cur.y + ady;
  int sw = screen_w();
  int sh = screen_h();
  if (nx < 0)
    nx = 0;
  if (ny < 0)
    ny = 0;
  if (nx >= sw)
    nx = sw - 1;
  if (ny >= sh)
    ny = sh - 1;
  mouse_cur.x = (int16_t)nx;
  mouse_cur.y = (int16_t)ny;
  mouse_cur.dx = (int8_t)((adx < -128) ? -128 : (adx > 127 ? 127 : adx));
  mouse_cur.dy = (int8_t)((ady < -128) ? -128 : (ady > 127 ? 127 : ady));

  /* Latch press edges while draining the IRQ ring (slow frames lose them). */
  if ((buttons & 1u) && !(mouse_cur.buttons & 1u)) {
    mouse_click_pending = 1;
    mouse_click_x = mouse_cur.x;
    mouse_click_y = mouse_cur.y;
  }
  mouse_cur.buttons = buttons;
}

void mouse_init(void) {
  mouse_r = mouse_w = 0;
  packet_idx = 0;
  mouse_click_pending = 0;
  mouse_cur.x = (int16_t)(screen_w() / 2);
  mouse_cur.y = (int16_t)(screen_h() / 2);
  mouse_cur.buttons = 0;
  mouse_cur.dx = mouse_cur.dy = 0;

  register_interrupt_handler(32 + 12, mouse_irq_handler);

  mouse_wait_write();
  outb(0x64, 0xA8);

  mouse_wait_write();
  outb(0x64, 0x20);
  mouse_wait_read();
  uint8_t status = inb(0x60);
  status |= 0x02;
  status |= 0x01;
  status &= (uint8_t)~0x20;
  mouse_wait_write();
  outb(0x64, 0x60);
  mouse_wait_write();
  outb(0x60, status);

  mouse_write(0xF6);
  (void)mouse_read();
  mouse_write(0xF4);
  (void)mouse_read();

  pic_unmask_irq(12);
}

void mouse_shutdown(void) {
  mouse_write(0xF5);
  (void)mouse_read();
  pic_mask_irq(12);
  register_interrupt_handler(32 + 12, 0);
}

void mouse_poll(mouse_state_t *out) {
  while (mouse_r != mouse_w) {
    uint8_t b = mouse_bytes[mouse_r];
    mouse_r = (uint16_t)((mouse_r + 1u) % MOUSE_RING);
    mouse_push_process(b);
  }
  if (out)
    *out = mouse_cur;
}

int mouse_left_pressed(const mouse_state_t *m) {
  return m && (m->buttons & 1u);
}

int mouse_left_clicked(const mouse_state_t *cur, const mouse_state_t *prev) {
  (void)cur;
  (void)prev;
  if (mouse_click_pending) {
    mouse_click_pending = 0;
    return 1;
  }
  return 0;
}

void mouse_click_coords(int *x, int *y) {
  if (x)
    *x = (int)mouse_click_x;
  if (y)
    *y = (int)mouse_click_y;
}

#endif
