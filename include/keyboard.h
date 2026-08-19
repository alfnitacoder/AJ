#ifndef KEYBOARD_H
#define KEYBOARD_H

// Special key constants for input_getkey()
enum {
  KEY_UP = 0x100,
  KEY_DOWN = 0x101,
  KEY_LEFT = 0x102,
  KEY_RIGHT = 0x103,
  KEY_DELETE = 0x104,
  KEY_INSERT = 0x105,
  KEY_HOME = 0x106,
  KEY_END = 0x107,
  KEY_PAGEUP = 0x108,
  KEY_PAGEDOWN = 0x109,
  KEY_F1 = 0x110,
  KEY_F2 = 0x111,
  KEY_F3 = 0x112,
  KEY_F4 = 0x113,
  KEY_F5 = 0x114,
  KEY_F6 = 0x115,
  KEY_F7 = 0x116,
  KEY_F8 = 0x117,
  KEY_F9 = 0x118,
  KEY_F10 = 0x119,
  KEY_F11 = 0x11A,
  KEY_F12 = 0x11B
};

/* Non-blocking keyboard input. input_getkey_noblock() returns raw PS/2
 * scancodes in VGA builds; input_getchar_noblock() translates to ASCII
 * (shift/caps handled) and returns KEY_* constants for special keys. */
int input_getkey_noblock(void);
int input_getchar_noblock(void);
int input_getkey(void);

#endif
