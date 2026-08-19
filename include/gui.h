#ifndef GUI_H
#define GUI_H

#ifndef AJOS_SERIAL_ONLY
/* Enter Mode 13h desktop; blocks until Quit / Esc. Restores text mode. */
void desktop_run(void);
#else
static inline void desktop_run(void) {}
#endif

#endif
