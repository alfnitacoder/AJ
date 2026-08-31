/* webreg.c - RAM registry of installed webapps (App Store client side).
 * See include/webreg.h. Single-threaded kernel: no locking needed. */
#include "webreg.h"

extern void log_writestring(const char *s);

typedef struct {
  int used;
  char name[32];
  int len;
  char buf[WEBREG_APPCAP];
} webreg_slot_t;

static webreg_slot_t webreg_slots[WEBREG_MAX];

static int name_eq(const char *a, const char *b)
{
  while (*a && *b)
  {
    if (*a++ != *b++)
      return 0;
  }
  return *a == *b;
}

int webreg_install(const char *name, const char *text, int len)
{
  if (!name || !text || len <= 0)
    return -1;
  int ni = 0;
  while (name[ni] && ni < 31)
  {
    char c = name[ni];
    if (c == '/' || c == '?' || c == ' ')
      break;
    ni++;
  }
  if (ni == 0)
    return -1;

  if (len > WEBREG_APPCAP)
    len = WEBREG_APPCAP;

  /* Replace an existing install of the same name first. */
  for (int i = 0; i < WEBREG_MAX; i++)
  {
    if (webreg_slots[i].used && name_eq(webreg_slots[i].name, name))
    {
      for (int j = 0; j < len; j++)
        webreg_slots[i].buf[j] = text[j];
      webreg_slots[i].buf[len] = 0;
      webreg_slots[i].len = len;
      return i;
    }
  }

  for (int i = 0; i < WEBREG_MAX; i++)
  {
    if (!webreg_slots[i].used)
    {
      webreg_slots[i].used = 1;
      int j = 0;
      while (j < ni)
      {
        webreg_slots[i].name[j] = name[j];
        j++;
      }
      webreg_slots[i].name[j] = 0;
      for (int k = 0; k < len; k++)
        webreg_slots[i].buf[k] = text[k];
      webreg_slots[i].buf[len] = 0;
      webreg_slots[i].len = len;
      return i;
    }
  }
  log_writestring("[webreg] registry full (8 apps)\n");
  return -1;
}

int webreg_lookup(const char *name, const char **out_text, int *out_len)
{
  if (!name)
    return 0;
  for (int i = 0; i < WEBREG_MAX; i++)
  {
    if (webreg_slots[i].used && name_eq(webreg_slots[i].name, name))
    {
      if (out_text)
        *out_text = webreg_slots[i].buf;
      if (out_len)
        *out_len = webreg_slots[i].len;
      return 1;
    }
  }
  return 0;
}

int webreg_count(void)
{
  int n = 0;
  for (int i = 0; i < WEBREG_MAX; i++)
    if (webreg_slots[i].used)
      n++;
  return n;
}

int webreg_list(char *buf, int cap)
{
  int n = 0;
  for (int i = 0; i < WEBREG_MAX && n < cap - 2; i++)
  {
    if (!webreg_slots[i].used)
      continue;
    int j = 0;
    while (webreg_slots[i].name[j] && n < cap - 2)
      buf[n++] = webreg_slots[i].name[j++];
    buf[n++] = '\n';
  }
  buf[n] = 0;
  return n;
}

int webreg_remove(const char *name)
{
  int removed = 0;
  for (int i = 0; i < WEBREG_MAX; i++)
  {
    if (!webreg_slots[i].used)
      continue;
    if (!name || name_eq(webreg_slots[i].name, name))
    {
      webreg_slots[i].used = 0;
      removed = 1;
    }
  }
  return removed;
}
