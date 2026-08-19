#ifndef MOUSE_H
#define MOUSE_H

#include <stdint.h>

typedef struct mouse_state {
  int16_t x;
  int16_t y;
  uint8_t buttons; /* bit0=L bit1=R bit2=M */
  int8_t dx;
  int8_t dy;
} mouse_state_t;

#ifndef AJOS_SERIAL_ONLY
void mouse_init(void);
void mouse_shutdown(void);
/* Drain IRQ packets and update absolute position (clamped to screen). */
void mouse_poll(mouse_state_t *out);
int mouse_left_pressed(const mouse_state_t *m);
int mouse_left_clicked(const mouse_state_t *cur, const mouse_state_t *prev);
/* Coordinates of the click consumed by the last mouse_left_clicked(). */
void mouse_click_coords(int *x, int *y);
#else
static inline void mouse_init(void) {}
static inline void mouse_shutdown(void) {}
static inline void mouse_poll(mouse_state_t *out) {
  if (out) {
    out->x = out->y = 0;
    out->buttons = 0;
    out->dx = out->dy = 0;
  }
}
static inline int mouse_left_pressed(const mouse_state_t *m) {
  (void)m;
  return 0;
}
static inline int mouse_left_clicked(const mouse_state_t *c,
                                     const mouse_state_t *p) {
  (void)c;
  (void)p;
  return 0;
}
static inline void mouse_click_coords(int *x, int *y) {
  if (x)
    *x = 0;
  if (y)
    *y = 0;
}
#endif

#endif
