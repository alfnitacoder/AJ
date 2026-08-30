#include "sftp.h"
#include "disk.h"
#include "fat.h"
#include "kernel.h"
#include "ramfs.h"
#include "ssh.h"
#include "vfs.h"
#include <stddef.h>
#include <stdint.h>

extern void *kmalloc(uint32_t size);
extern void kfree(void *ptr);
extern void mem_set(uint8_t *dst, uint8_t v, uint32_t n);
extern void mem_copy(void *dest, const void *src, uint32_t n);
extern size_t kstrlen(const char *s);
extern int kstreq(const char *a, const char *b);
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);

/* draft-ietf-secsh-filexfer-02 */
#define SSH_FXP_INIT 1
#define SSH_FXP_VERSION 2
#define SSH_FXP_OPEN 3
#define SSH_FXP_CLOSE 4
#define SSH_FXP_READ 5
#define SSH_FXP_WRITE 6
#define SSH_FXP_LSTAT 7
#define SSH_FXP_FSTAT 8
#define SSH_FXP_SETSTAT 9
#define SSH_FXP_FSETSTAT 10
#define SSH_FXP_OPENDIR 11
#define SSH_FXP_READDIR 12
#define SSH_FXP_REMOVE 13
#define SSH_FXP_MKDIR 14
#define SSH_FXP_RMDIR 15
#define SSH_FXP_REALPATH 16
#define SSH_FXP_STAT 17
#define SSH_FXP_RENAME 18
#define SSH_FXP_READLINK 19
#define SSH_FXP_SYMLINK 20
#define SSH_FXP_STATUS 101
#define SSH_FXP_HANDLE 102
#define SSH_FXP_DATA 103
#define SSH_FXP_NAME 104
#define SSH_FXP_ATTRS 105
#define SSH_FXP_EXTENDED 200
#define SSH_FXP_EXTENDED_REPLY 201

#define SSH_FX_OK 0
#define SSH_FX_EOF 1
#define SSH_FX_NO_SUCH_FILE 2
#define SSH_FX_PERMISSION_DENIED 3
#define SSH_FX_FAILURE 4
#define SSH_FX_BAD_MESSAGE 5
#define SSH_FX_OP_UNSUPPORTED 8

#define SSH_FILEXFER_ATTR_SIZE 0x00000001u
#define SSH_FILEXFER_ATTR_UIDGID 0x00000002u
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004u
#define SSH_FILEXFER_ATTR_ACMODTIME 0x00000008u
#define SSH_FILEXFER_ATTR_EXTENDED 0x80000000u

#define SSH_FXF_READ 0x00000001u
#define SSH_FXF_WRITE 0x00000002u
#define SSH_FXF_APPEND 0x00000004u
#define SSH_FXF_CREAT 0x00000008u
#define SSH_FXF_TRUNC 0x00000010u
#define SSH_FXF_EXCL 0x00000020u

#define S_IFDIR 0040000
#define S_IFREG 0100000

#define SFTP_VERSION 3
#define SFTP_MAX_SESSIONS 4
#define SFTP_MAX_HANDLES 12
#define SFTP_MAX_PATH 256
/* Must hold one full SFTP message: OpenSSH pipelines WRITE requests with
 * 32768-byte data chunks -> ~32.9 KB per message (length prefix + WRITE hdr
 * + payload). At 32768 the message did not fit and sftp_feed's overflow
 * handler dropped the ENTIRE ring contents, so big uploads hung forever.
 * 64KB also covers sshfs (default max_write 32KB, SSH packet cap 35000). */
#define SFTP_RX_MAX 65536u
#define SFTP_MAX_FILE 262144u
#define SFTP_DIR_MAX 64
#define SFTP_NAME_MAX 80
#define SFTP_DATA_MAX 8192u
#define SFTP_UID 1000u
#define SFTP_GID 1000u
#define SFTP_ATTR_BYTES 32u
#define SFTP_DEFAULT_MTIME 1704067200u /* 2024-01-01 00:00:00 UTC */

struct sftp_dirent
{
  char name[SFTP_NAME_MAX];
  char name83[13];
  uint8_t is_dir;
  uint32_t size;
  uint32_t mtime;
};

struct sftp_attrs
{
  uint32_t flags;
  uint32_t size;
  uint32_t uid;
  uint32_t gid;
  uint32_t perms;
  uint32_t atime;
  uint32_t mtime;
  uint8_t has_size;
};

struct sftp_handle
{
  uint8_t in_use;
  uint8_t is_dir;
  uint8_t dirty;
  uint8_t eof_sent;
  uint8_t load_tried;
  uint32_t id;
  uint32_t flags;
  uint32_t mtime;
  char path[SFTP_MAX_PATH];
  uint8_t *data;
  uint32_t size;
  uint32_t cap;
  uint32_t dir_count;
  uint32_t dir_index;
  struct sftp_dirent dirents[SFTP_DIR_MAX];
};

struct sftp_sess
{
  struct ssh_connection *conn;
  uint8_t *rx;
  uint32_t rx_len;
  uint32_t rx_cap;
  uint32_t next_id;
  struct sftp_handle handles[SFTP_MAX_HANDLES];
  /* Static RX: kmalloc(32KB) via PMM during CHANNEL_REQUEST wedged the
   * guest (IRQs/tcp_input). BSS is NOLOAD so this does not grow kernel.bin. */
  uint8_t rx_store[SFTP_RX_MAX];
};

static struct sftp_sess sftp_sessions[SFTP_MAX_SESSIONS];

static uint32_t sftp_rd_u32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void sftp_wr_u32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void sftp_wr_u64(uint8_t *p, uint32_t lo)
{
  sftp_wr_u32(p, 0);
  sftp_wr_u32(p + 4, lo);
}

static int sftp_name_eq_ci(const char *a, const char *b)
{
  if (!a || !b)
    return 0;
  while (*a && *b)
  {
    char ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z')
      ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z')
      cb = (char)(cb - 'A' + 'a');
    if (ca != cb)
      return 0;
    a++;
    b++;
  }
  return *a == *b;
}

static int sftp_is_dot_name(const char *n)
{
  return (n[0] == '.' && n[1] == '\0') ||
         (n[0] == '.' && n[1] == '.' && n[2] == '\0');
}

static void sftp_strip_slash_copy(const char *in, char *out, uint32_t cap)
{
  while (*in == '/')
    in++;
  uint32_t i = 0;
  while (in[i] && i + 1 < cap)
  {
    out[i] = in[i];
    i++;
  }
  out[i] = '\0';
}

/* Canonical absolute path: always starts with '/', no trailing slash except root. */
static int sftp_canon(const char *in, char *out, uint32_t cap)
{
  if (!in || !out || cap < 2)
    return 0;
  char parts[16][SFTP_NAME_MAX];
  int nparts = 0;
  const char *p = in;
  if (*p == '\0' || (*p == '.' && p[1] == '\0'))
  {
    out[0] = '/';
    out[1] = '\0';
    return 1;
  }
  while (*p)
  {
    while (*p == '/')
      p++;
    if (*p == '\0')
      break;
    char seg[SFTP_NAME_MAX];
    int si = 0;
    while (*p && *p != '/' && si < (int)sizeof(seg) - 1)
      seg[si++] = *p++;
    seg[si] = '\0';
    if (seg[0] == '\0' || (seg[0] == '.' && seg[1] == '\0'))
      continue;
    if (seg[0] == '.' && seg[1] == '.' && seg[2] == '\0')
    {
      if (nparts > 0)
        nparts--;
      continue;
    }
    if (nparts >= 16)
      return 0;
    int k = 0;
    while (seg[k] && k < SFTP_NAME_MAX - 1)
    {
      parts[nparts][k] = seg[k];
      k++;
    }
    parts[nparts][k] = '\0';
    nparts++;
  }
  if (nparts == 0)
  {
    out[0] = '/';
    out[1] = '\0';
    return 1;
  }
  uint32_t o = 0;
  for (int i = 0; i < nparts; i++)
  {
    if (o + 1 >= cap)
      return 0;
    out[o++] = '/';
    for (int k = 0; parts[i][k]; k++)
    {
      if (o + 1 >= cap)
        return 0;
      out[o++] = parts[i][k];
    }
  }
  out[o] = '\0';
  return 1;
}

static int sftp_get_str(const uint8_t *p, int len, int *off, char *out,
                        int outcap)
{
  if (*off + 4 > len)
    return 0;
  uint32_t n = sftp_rd_u32(p + *off);
  *off += 4;
  if (n > 4096u || *off + (int)n > len)
    return 0;
  int cpy = (int)n;
  if (cpy >= outcap)
    cpy = outcap - 1;
  for (int i = 0; i < cpy; i++)
    out[i] = (char)p[*off + i];
  out[cpy] = '\0';
  *off += (int)n;
  return 1;
}

static int sftp_get_handle(const uint8_t *p, int len, int *off, uint32_t *id)
{
  if (*off + 4 > len)
    return 0;
  uint32_t n = sftp_rd_u32(p + *off);
  *off += 4;
  if (n != 4 || *off + 4 > len)
    return 0;
  *id = sftp_rd_u32(p + *off);
  *off += 4;
  return 1;
}

static int sftp_parse_attrs(const uint8_t *p, int len, int *off,
                            struct sftp_attrs *out)
{
  struct sftp_attrs a;
  mem_set((uint8_t *)&a, 0, sizeof(a));
  if (*off + 4 > len)
    return 0;
  a.flags = sftp_rd_u32(p + *off);
  *off += 4;
  if (a.flags & SSH_FILEXFER_ATTR_SIZE)
  {
    if (*off + 8 > len)
      return 0;
    a.size = sftp_rd_u32(p + *off + 4);
    a.has_size = 1;
    *off += 8;
  }
  if (a.flags & SSH_FILEXFER_ATTR_UIDGID)
  {
    if (*off + 8 > len)
      return 0;
    a.uid = sftp_rd_u32(p + *off);
    a.gid = sftp_rd_u32(p + *off + 4);
    *off += 8;
  }
  if (a.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
  {
    if (*off + 4 > len)
      return 0;
    a.perms = sftp_rd_u32(p + *off);
    *off += 4;
  }
  if (a.flags & SSH_FILEXFER_ATTR_ACMODTIME)
  {
    if (*off + 8 > len)
      return 0;
    a.atime = sftp_rd_u32(p + *off);
    a.mtime = sftp_rd_u32(p + *off + 4);
    *off += 8;
  }
  if (a.flags & SSH_FILEXFER_ATTR_EXTENDED)
  {
    if (*off + 4 > len)
      return 0;
    uint32_t ext = sftp_rd_u32(p + *off);
    *off += 4;
    for (uint32_t i = 0; i < ext; i++)
    {
      if (*off + 4 > len)
        return 0;
      uint32_t n = sftp_rd_u32(p + *off);
      *off += 4;
      if (*off + (int)n > len)
        return 0;
      *off += (int)n;
      if (*off + 4 > len)
        return 0;
      n = sftp_rd_u32(p + *off);
      *off += 4;
      if (*off + (int)n > len)
        return 0;
      *off += (int)n;
    }
  }
  if (out)
    *out = a;
  return 1;
}

static int sftp_skip_attrs(const uint8_t *p, int len, int *off)
{
  return sftp_parse_attrs(p, len, off, 0);
}

static uint32_t sftp_attr_perms(int is_dir)
{
  return is_dir ? (uint32_t)(S_IFDIR | 0755) : (uint32_t)(S_IFREG | 0644);
}

static uint32_t sftp_fat_unix(uint16_t date, uint16_t time)
{
  static const uint16_t mdays[12] = {0, 31, 59, 90, 120, 151,
                                     181, 212, 243, 273, 304, 334};
  uint32_t year = 1980u + (uint32_t)(date >> 9);
  uint32_t month = (uint32_t)((date >> 5) & 15);
  uint32_t day = (uint32_t)(date & 31);
  uint32_t hour = (uint32_t)(time >> 11);
  uint32_t min = (uint32_t)((time >> 5) & 63);
  uint32_t sec = (uint32_t)(time & 31) * 2u;
  uint32_t y;
  uint32_t days;
  if (date == 0)
    return SFTP_DEFAULT_MTIME;
  if (month < 1 || month > 12)
    month = 1;
  if (day < 1)
    day = 1;
  y = year;
  days = (y - 1970u) * 365u + (y - 1969u) / 4u;
  days += mdays[month - 1];
  if (month > 2 && (y % 4u) == 0)
    days++;
  days += day - 1u;
  return days * 86400u + hour * 3600u + min * 60u + sec;
}

static uint32_t sftp_put_attrs(uint8_t *d, int is_dir, uint32_t size,
                               uint32_t mtime)
{
  uint32_t flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
                   SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
  uint32_t ts = mtime ? mtime : SFTP_DEFAULT_MTIME;
  sftp_wr_u32(d, flags);
  sftp_wr_u64(d + 4, size);
  sftp_wr_u32(d + 12, SFTP_UID);
  sftp_wr_u32(d + 16, SFTP_GID);
  sftp_wr_u32(d + 20, sftp_attr_perms(is_dir));
  sftp_wr_u32(d + 24, ts);
  sftp_wr_u32(d + 28, ts);
  return SFTP_ATTR_BYTES;
}

static uint32_t sftp_put_str(uint8_t *d, const char *s)
{
  uint32_t n = 0;
  while (s[n])
    n++;
  sftp_wr_u32(d, n);
  if (n)
    mem_copy(d + 4, s, n);
  return 4 + n;
}

static uint8_t sftp_pkt_scratch[16384];
/* Incoming SFTP payload copy so dispatch can consume RX before I/O/TX. */
static uint8_t sftp_pkt_in[SFTP_RX_MAX];
static uint8_t sftp_dispatching;
/* Live floppy root sits past the 632-sector boot cache; BIOS reads from the
 * SSH path return empty or hang. Snapshot at disk_init uses the wrong LBA.
 * Cache the real root once at boot (same read user_init already does). */
static uint8_t sftp_boot_root[16384];
static uint32_t sftp_boot_root_len;
static uint8_t sftp_boot_root_ready;

/* Overlay on the boot-root snapshot so sshfs sees creates/deletes without
 * re-reading the floppy from the SSH path (that read is what PR #1 cached). */
#define SFTP_ROOT_DELTA 24
static struct sftp_dirent sftp_root_extra[SFTP_ROOT_DELTA];
static uint32_t sftp_root_extra_n;
static char sftp_root_gone[SFTP_ROOT_DELTA][SFTP_NAME_MAX];
static uint32_t sftp_root_gone_n;

void sftp_cache_boot_root(void)
{
  extern fat12_ctx fat_global_ctx;
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  if (!fat12_read_root_dir(&fat_global_ctx, &buf, &bytes) || !buf || bytes < 32u)
    return;
  if (bytes > sizeof(sftp_boot_root))
    bytes = sizeof(sftp_boot_root);
  mem_copy(sftp_boot_root, buf, bytes);
  sftp_boot_root_len = bytes;
  sftp_boot_root_ready = 1;
  kfree(buf);
}

static int sftp_path_on_boot_fat(const char *canon)
{
  struct vfs_ctx *vfs = vfs_get_global();
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs || !canon)
    return 0;
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  return kstreq(vfs->mounts[mount_id].mount_point, "/");
}

static int sftp_root_is_direct(const char *canon)
{
  const char *p;
  if (!canon || canon[0] != '/')
    return 0;
  if (canon[1] == '\0')
    return 0;
  p = canon + 1;
  while (*p)
  {
    if (*p == '/')
      return 0;
    p++;
  }
  return sftp_path_on_boot_fat(canon);
}

static void sftp_name_copy(char *dst, uint32_t cap, const char *src)
{
  uint32_t i = 0;
  while (src[i] && i + 1 < cap)
  {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
}

static const char *sftp_base_name(const char *canon)
{
  const char *b = canon;
  const char *p = canon;
  if (!p)
    return "";
  while (*p)
  {
    if (*p == '/')
      b = p + 1;
    p++;
  }
  return b;
}

static void sftp_root_note(const char *canon, int is_dir, uint32_t size, int gone)
{
  const char *name;
  uint32_t i;
  if (!sftp_root_is_direct(canon))
    return;
  name = sftp_base_name(canon);
  if (!name[0] || sftp_is_dot_name(name))
    return;
  for (i = 0; i < sftp_root_gone_n; i++)
  {
    if (sftp_name_eq_ci(sftp_root_gone[i], name))
    {
      uint32_t j;
      for (j = i + 1; j < sftp_root_gone_n; j++)
        sftp_name_copy(sftp_root_gone[j - 1], SFTP_NAME_MAX, sftp_root_gone[j]);
      sftp_root_gone_n--;
      break;
    }
  }
  for (i = 0; i < sftp_root_extra_n; i++)
  {
    if (sftp_name_eq_ci(sftp_root_extra[i].name, name) ||
        (sftp_root_extra[i].name83[0] &&
         sftp_name_eq_ci(sftp_root_extra[i].name83, name)))
    {
      uint32_t j;
      for (j = i + 1; j < sftp_root_extra_n; j++)
        sftp_root_extra[j - 1] = sftp_root_extra[j];
      sftp_root_extra_n--;
      break;
    }
  }
  if (gone)
  {
    if (sftp_root_gone_n < SFTP_ROOT_DELTA)
      sftp_name_copy(sftp_root_gone[sftp_root_gone_n++], SFTP_NAME_MAX, name);
    return;
  }
  if (sftp_root_extra_n < SFTP_ROOT_DELTA)
  {
    struct sftp_dirent *e = &sftp_root_extra[sftp_root_extra_n++];
    mem_set((uint8_t *)e, 0, sizeof(*e));
    sftp_name_copy(e->name, SFTP_NAME_MAX, name);
    e->is_dir = (uint8_t)is_dir;
    e->size = size;
    e->mtime = SFTP_DEFAULT_MTIME;
  }
}

static int sftp_root_gone_match(const char *name)
{
  uint32_t i;
  for (i = 0; i < sftp_root_gone_n; i++)
    if (sftp_name_eq_ci(sftp_root_gone[i], name))
      return 1;
  return 0;
}

static void sftp_reply(struct ssh_connection *conn, const uint8_t *payload,
                       uint32_t plen)
{
  uint8_t small[512];
  uint8_t *pkt;
  /* Build-in-place: NAME/DATA already live at sftp_pkt_scratch+4. */
  if (payload == sftp_pkt_scratch + 4 && 4u + plen <= sizeof(sftp_pkt_scratch))
  {
    sftp_wr_u32(sftp_pkt_scratch, plen);
    ssh_channel_write(conn, sftp_pkt_scratch, 4u + plen);
    return;
  }
  if (4u + plen <= sizeof(small))
    pkt = small;
  else if (4u + plen <= sizeof(sftp_pkt_scratch))
    pkt = sftp_pkt_scratch;
  else
    return;
  sftp_wr_u32(pkt, plen);
  if (plen)
    mem_copy(pkt + 4, payload, plen);
  ssh_channel_write(conn, pkt, 4u + plen);
}

static void sftp_status(struct ssh_connection *conn, uint32_t id, uint32_t code,
                        const char *msg)
{
  uint8_t buf[128];
  uint32_t ml = 0;
  if (msg)
    while (msg[ml])
      ml++;
  if (4u + 1u + 4u + 4u + 4u + ml + 4u > sizeof(buf))
    ml = 0;
  buf[0] = SSH_FXP_STATUS;
  sftp_wr_u32(buf + 1, id);
  sftp_wr_u32(buf + 5, code);
  sftp_wr_u32(buf + 9, ml);
  uint32_t o = 13;
  for (uint32_t i = 0; i < ml; i++)
    buf[o++] = (uint8_t)msg[i];
  sftp_wr_u32(buf + o, 0); /* language tag */
  o += 4;
  sftp_reply(conn, buf, o);
}

static void sftp_send_handle(struct ssh_connection *conn, uint32_t id,
                             uint32_t hid)
{
  uint8_t buf[16];
  buf[0] = SSH_FXP_HANDLE;
  sftp_wr_u32(buf + 1, id);
  sftp_wr_u32(buf + 5, 4);
  sftp_wr_u32(buf + 9, hid);
  sftp_reply(conn, buf, 13);
}

static void sftp_send_attrs(struct ssh_connection *conn, uint32_t id, int is_dir,
                            uint32_t size, uint32_t mtime)
{
  uint8_t buf[48];
  buf[0] = SSH_FXP_ATTRS;
  sftp_wr_u32(buf + 1, id);
  uint32_t n = sftp_put_attrs(buf + 5, is_dir, size, mtime);
  sftp_reply(conn, buf, 5 + n);
}

static struct sftp_sess *sftp_find(struct ssh_connection *conn)
{
  for (int i = 0; i < SFTP_MAX_SESSIONS; i++)
    if (sftp_sessions[i].conn == conn)
      return &sftp_sessions[i];
  return 0;
}

static void sftp_handle_free(struct sftp_handle *h)
{
  if (!h->in_use)
    return;
  if (h->data)
  {
    kfree(h->data);
    h->data = 0;
  }
  mem_set((uint8_t *)h, 0, sizeof(*h));
}

static void sftp_sess_reset(struct sftp_sess *s)
{
  if (!s)
    return;
  for (int i = 0; i < SFTP_MAX_HANDLES; i++)
    sftp_handle_free(&s->handles[i]);
  s->conn = 0;
  s->rx = 0;
  s->rx_len = 0;
  s->rx_cap = 0;
  s->next_id = 0;
}

static struct sftp_handle *sftp_handle_by_id(struct sftp_sess *s, uint32_t id)
{
  for (int i = 0; i < SFTP_MAX_HANDLES; i++)
    if (s->handles[i].in_use && s->handles[i].id == id)
      return &s->handles[i];
  return 0;
}

static struct sftp_handle *sftp_handle_alloc(struct sftp_sess *s)
{
  for (int i = 0; i < SFTP_MAX_HANDLES; i++)
  {
    if (!s->handles[i].in_use)
    {
      mem_set((uint8_t *)&s->handles[i], 0, sizeof(s->handles[i]));
      s->handles[i].in_use = 1;
      s->next_id++;
      if (s->next_id == 0)
        s->next_id = 1;
      s->handles[i].id = s->next_id;
      return &s->handles[i];
    }
  }
  return 0;
}

static int sftp_path_copy(char *dst, const char *src)
{
  uint32_t i = 0;
  while (src[i] && i + 1 < SFTP_MAX_PATH)
  {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
  return src[i] == '\0';
}

static fat12_ctx *sftp_boot_fat(struct vfs_mount *m)
{
  extern fat12_ctx fat_global_ctx;
  if (m && kstreq(m->mount_point, "/"))
    return &fat_global_ctx;
  return m ? (fat12_ctx *)m->fs_ctx : 0;
}

/* 1 = filled *out, 0 = skip, -1 = end of directory. dir_buf is the directory
 * image so LFN entries immediately before the 8.3 slot can be recovered. */
static int sftp_dirent_from_raw(const uint8_t *dir_buf, uint32_t byte_idx,
                                struct sftp_dirent *out)
{
  const struct fat12_dirent *e =
      (const struct fat12_dirent *)(dir_buf + byte_idx);
  char formatted[13];
  uint32_t k;
  if (e->name[0] == 0x00)
    return -1;
  if (e->name[0] == 0xE5 || (e->attr & 0x08) || e->attr == FAT_ATTR_LFN)
    return 0;
  fat12_format_name(e->name, formatted);
  if (formatted[0] == '\0' || sftp_is_dot_name(formatted))
    return 0;
  fat12_display_name(dir_buf, byte_idx, out->name, SFTP_NAME_MAX);
  if (out->name[0] == '\0')
  {
    k = 0;
    while (formatted[k] && k + 1 < SFTP_NAME_MAX)
    {
      out->name[k] = formatted[k];
      k++;
    }
    out->name[k] = '\0';
  }
  k = 0;
  while (formatted[k] && k < 12)
  {
    out->name83[k] = formatted[k];
    k++;
  }
  out->name83[k] = '\0';
  out->is_dir = (e->attr & 0x10) ? 1 : 0;
  out->size = e->size;
  out->mtime = sftp_fat_unix(e->wrt_date, e->wrt_time);
  return 1;
}

static int sftp_ent_match(const struct sftp_dirent *e, const char *name)
{
  if (!e || !name)
    return 0;
  if (sftp_name_eq_ci(e->name, name))
    return 1;
  if (e->name83[0] && sftp_name_eq_ci(e->name83, name))
    return 1;
  return 0;
}

static int sftp_fat_list_buf(const uint8_t *dir_buf, uint32_t dir_bytes,
                             struct sftp_dirent *ents, uint32_t max,
                             uint32_t *out_n)
{
  uint32_t n = 0;
  uint32_t entries;
  uint32_t i;
  if (!dir_buf || !ents || !out_n || max == 0)
    return 0;
  entries = dir_bytes / 32u;
  for (i = 0; i < entries && n < max; i++)
  {
    int r = sftp_dirent_from_raw(dir_buf, i * 32u, &ents[n]);
    if (r < 0)
      break;
    if (r > 0)
    {
      uint32_t k;
      int ok_name = 1;
      for (k = 0; ents[n].name[k]; k++)
      {
        char c = ents[n].name[k];
        if (c < 32 || c > 126)
          ok_name = 0;
      }
      if (ok_name)
        n++;
    }
  }
  *out_n = n;
  return 1;
}

static int sftp_fat_list_sectors(uint8_t drive, uint32_t lba, uint16_t nsec,
                                 struct sftp_dirent *ents, uint32_t max,
                                 uint32_t *out_n)
{
  /* Two-sector window so LFN that starts in the previous sector still
   * round-trips with fat12_display_name. */
  static uint8_t window[1024];
  uint32_t n = 0;
  uint16_t s;
  if (!ents || !out_n || max == 0 || nsec == 0)
    return 0;
  mem_set(window, 0, 512);
  for (s = 0; s < nsec && n < max; s++)
  {
    int i;
    if (!disk_read_sector(drive, lba + s, window + 512))
      return 0;
    for (i = 0; i < 16 && n < max; i++)
    {
      int r = sftp_dirent_from_raw(window, 512u + (uint32_t)i * 32u, &ents[n]);
      if (r < 0)
      {
        *out_n = n;
        return 1;
      }
      if (r > 0)
        n++;
    }
    mem_copy(window, window + 512, 512);
  }
  *out_n = n;
  return 1;
}

static void sftp_apply_root_overlay(struct sftp_dirent *ents, uint32_t max,
                                    uint32_t *n)
{
  uint32_t i;
  uint32_t w = 0;
  if (!ents || !n)
    return;
  for (i = 0; i < *n; i++)
  {
    if (sftp_root_gone_match(ents[i].name) ||
        (ents[i].name83[0] && sftp_root_gone_match(ents[i].name83)))
      continue;
    if (w != i)
      ents[w] = ents[i];
    w++;
  }
  *n = w;
  for (i = 0; i < sftp_root_extra_n && *n < max; i++)
  {
    uint32_t j;
    int found = 0;
    for (j = 0; j < *n; j++)
    {
      if (sftp_ent_match(&ents[j], sftp_root_extra[i].name))
      {
        ents[j] = sftp_root_extra[i];
        found = 1;
        break;
      }
    }
    if (!found)
    {
      ents[*n] = sftp_root_extra[i];
      (*n)++;
    }
  }
}

static int sftp_fat_list(fat12_ctx *ctx, const char *fs_path,
                         struct sftp_dirent *ents, uint32_t max,
                         uint32_t *out_n)
{
  extern fat12_ctx fat_global_ctx;
  const char *p = fs_path ? fs_path : "/";
  uint8_t spc;
  int ok;
  uint32_t n = 0;
  if (!ctx || !ents || !out_n)
    return 0;
  if (p[0] == '\0' || (p[0] == '/' && p[1] == '\0'))
  {
    if (sftp_boot_root_ready && sftp_boot_root_len && ctx == &fat_global_ctx)
      ok = sftp_fat_list_buf(sftp_boot_root, sftp_boot_root_len, ents, max, &n);
    else
      ok = sftp_fat_list_sectors(ctx->drive, ctx->root_lba, ctx->root_sectors,
                                 ents, max, &n);
    if (!ok)
      return 0;
    if (ctx == &fat_global_ctx)
      sftp_apply_root_overlay(ents, max, &n);
    *out_n = n;
    return 1;
  }
  {
    int dok = 0;
    const char *rp = p;
    uint16_t cluster;
    if (*rp == '/')
      rp++;
    cluster = fat12_resolve_dir(ctx, 0, rp, &dok);
    if (!dok)
      return 0;
    if (cluster == 0)
      ok = sftp_fat_list_sectors(ctx->drive, ctx->root_lba, ctx->root_sectors,
                                 ents, max, &n);
    else
    {
      /* First cluster only — enough for FAT12 floppy dirs; no kmalloc. */
      spc = ctx->bpb.sectors_per_cluster;
      if (spc == 0)
        spc = 1;
      ok = sftp_fat_list_sectors(ctx->drive, fat12_cluster_lba(ctx, cluster),
                                 spc, ents, max, &n);
    }
    if (!ok)
      return 0;
    *out_n = n;
    return 1;
  }
}

static int sftp_fat_stat(fat12_ctx *ctx, const char *fs_path, int *is_dir,
                         uint32_t *size, uint32_t *mtime)
{
  extern fat12_ctx fat_global_ctx;
  if (ctx != &fat_global_ctx)
    fat12_reload(ctx);
  const char *p = fs_path ? fs_path : "/";
  if (p[0] == '\0' || (p[0] == '/' && p[1] == '\0'))
  {
    *is_dir = 1;
    *size = 0;
    if (mtime)
      *mtime = SFTP_DEFAULT_MTIME;
    return 1;
  }
  /* Do not fat12_resolve_dir here: it kmallocs the whole root via
   * fat12_find_in_dir. List the parent sector-by-sector instead. */
  const char *rp = p;
  if (*rp == '/')
    rp++;
  char parent[SFTP_MAX_PATH];
  char name[SFTP_NAME_MAX];
  const char *last = rp;
  for (const char *q = rp; *q; q++)
    if (*q == '/')
      last = q + 1;
  uint32_t ni = 0;
  while (last[ni] && ni + 1 < sizeof(name))
  {
    name[ni] = last[ni];
    ni++;
  }
  name[ni] = '\0';
  if (last == rp)
  {
    parent[0] = '/';
    parent[1] = '\0';
  }
  else
  {
    uint32_t pl = (uint32_t)(last - rp);
    if (pl > 0 && rp[pl - 1] == '/')
      pl--;
    parent[0] = '/';
    uint32_t o = 1;
    for (uint32_t i = 0; i < pl && o + 1 < sizeof(parent); i++)
      parent[o++] = rp[i];
    parent[o] = '\0';
  }
  static struct sftp_dirent sftp_stat_ents[SFTP_DIR_MAX];
  uint32_t n = 0;
  if (!sftp_fat_list(ctx, parent, sftp_stat_ents, SFTP_DIR_MAX, &n))
    return 0;
  for (uint32_t i = 0; i < n; i++)
  {
    if (sftp_ent_match(&sftp_stat_ents[i], name))
    {
      *is_dir = sftp_stat_ents[i].is_dir;
      *size = sftp_stat_ents[i].size;
      if (mtime)
        *mtime = sftp_stat_ents[i].mtime ? sftp_stat_ents[i].mtime
                                         : SFTP_DEFAULT_MTIME;
      return 1;
    }
  }
  return 0;
}

static int sftp_ram_name(const char *fs_path, char *out, uint32_t cap)
{
  sftp_strip_slash_copy(fs_path ? fs_path : "", out, cap);
  return out[0] != '\0';
}

static int sftp_path_info(const char *canon, int *is_dir, uint32_t *size,
                          uint32_t *mtime)
{
  struct vfs_ctx *vfs = vfs_get_global();
  if (!vfs)
    return 0;
  if (canon[0] == '/' && canon[1] == '\0')
  {
    *is_dir = 1;
    *size = 0;
    if (mtime)
      *mtime = SFTP_DEFAULT_MTIME;
    return 1;
  }
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  /* Exact mount point (e.g. /tmp, /mnt) is a directory. */
  if (kstreq(canon, m->mount_point) ||
      (fs_path[0] == '/' && fs_path[1] == '\0'))
  {
    *is_dir = 1;
    *size = 0;
    if (mtime)
      *mtime = SFTP_DEFAULT_MTIME;
    return 1;
  }
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    fat12_ctx *fctx = sftp_boot_fat(m);
    if (!fctx)
      return 0;
    return sftp_fat_stat(fctx, fs_path, is_dir, size, mtime);
  }
  if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    char rn[SFTP_MAX_PATH];
    if (!sftp_ram_name(fs_path, rn, sizeof(rn)))
      return 0;
    struct ramfs_ctx *rc = (struct ramfs_ctx *)m->fs_ctx;
    if (!ramfs_get_file_size(rc, rn, size))
      return 0;
    *is_dir = 0;
    if (mtime)
      *mtime = SFTP_DEFAULT_MTIME;
    return 1;
  }
  return 0;
}

static int sftp_list_path(const char *canon, struct sftp_dirent *ents,
                          uint32_t max, uint32_t *out_n)
{
  struct vfs_ctx *vfs = vfs_get_global();
  if (!vfs || !ents || !out_n || max == 0)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  mem_set((uint8_t *)ents, 0, sizeof(struct sftp_dirent) * max);
  uint32_t n = 0;
  int ok = 0;
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    fat12_ctx *fctx = sftp_boot_fat(m);
    if (!fctx)
      return 0;
    ok = sftp_fat_list(fctx, fs_path, ents, max, &n);
  }
  else if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    /* Walk the ramfs table directly — ramfs_list_files kmallocs. */
    struct ramfs_ctx *rc = (struct ramfs_ctx *)m->fs_ctx;
    ok = 1;
    for (int i = 0; rc && i < RAMFS_MAX_FILES && n < max; i++)
    {
      if (!rc->files[i].in_use)
        continue;
      const char *nm = rc->files[i].name;
      while (*nm == '/')
        nm++;
      uint32_t k = 0;
      while (nm[k] && k + 1 < SFTP_NAME_MAX)
      {
        ents[n].name[k] = nm[k];
        k++;
      }
      ents[n].name[k] = '\0';
      ents[n].name83[0] = '\0';
      ents[n].is_dir = 0;
      ents[n].size = rc->files[i].size;
      ents[n].mtime = rc->files[i].mtime ? rc->files[i].mtime
                                         : SFTP_DEFAULT_MTIME;
      n++;
    }
  }
  if (!ok)
    return 0;
  /* sshfs expects "." / ".." as the first names in READDIR. */
  if (max >= 2)
  {
    uint32_t keep = n;
    uint32_t dest = max - 2;
    if (keep > dest)
      keep = dest;
    if (keep)
    {
      uint32_t i = keep;
      while (i > 0)
      {
        i--;
        ents[i + 2] = ents[i];
      }
    }
    mem_set((uint8_t *)&ents[0], 0, sizeof(ents[0]));
    ents[0].name[0] = '.';
    ents[0].is_dir = 1;
    ents[0].mtime = SFTP_DEFAULT_MTIME;
    mem_set((uint8_t *)&ents[1], 0, sizeof(ents[1]));
    ents[1].name[0] = '.';
    ents[1].name[1] = '.';
    ents[1].is_dir = 1;
    ents[1].mtime = SFTP_DEFAULT_MTIME;
    n = keep + 2;
  }
  *out_n = n;
  return 1;
}

static int sftp_load_file(const char *canon, uint8_t **data, uint32_t *size)
{
  struct vfs_ctx *vfs = vfs_get_global();
  if (!vfs)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    /* Same path as `ssh ... cat`: fresh ctx + BPB. fat_global_ctx root_lba
     * can miss the floppy cache and fail to find README.TXT. */
    if (kstreq(m->mount_point, "/"))
      return fat12_read_file_to_ram(fs_path, data, size);
    fat12_ctx *ctx = sftp_boot_fat(m);
    if (!ctx)
      return 0;
    return fat12_read_file_to_ram_ex_max(ctx, fs_path, data, size, SFTP_MAX_FILE);
  }
  if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    char rn[SFTP_MAX_PATH];
    if (!sftp_ram_name(fs_path, rn, sizeof(rn)))
      return 0;
    return ramfs_read_file((struct ramfs_ctx *)m->fs_ctx, rn, data, size);
  }
  return 0;
}

static int sftp_ensure_loaded(struct sftp_handle *h)
{
  if (!h || h->is_dir)
    return 0;
  if (h->data)
    return 1;
  if (h->load_tried)
    return 0;
  h->load_tried = 1;
  uint8_t *data = 0;
  uint32_t size = 0;
  if (!sftp_load_file(h->path, &data, &size))
    return 0;
  h->data = data;
  h->size = size;
  h->cap = size;
  return 1;
}

static int sftp_store_file(const char *canon, const uint8_t *data, uint32_t size)
{
  struct vfs_ctx *vfs = vfs_get_global();
  int ok = 0;
  if (!vfs)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  uint8_t dummy = 0;
  const uint8_t *src = data ? data : &dummy;
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    if (kstreq(m->mount_point, "/"))
      ok = fat12_write_file(fs_path, src, size);
    else
    {
      fat12_ctx *ctx = (fat12_ctx *)m->fs_ctx;
      fat12_reload(ctx);
      ok = fat12_write_file_ex(ctx, fs_path, src, size);
    }
  }
  else if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    char rn[SFTP_MAX_PATH];
    if (!sftp_ram_name(fs_path, rn, sizeof(rn)))
      return 0;
    struct ramfs_ctx *rc = (struct ramfs_ctx *)m->fs_ctx;
    if (size == 0)
      ok = ramfs_write_file(rc, rn, &dummy, 0) || ramfs_create_file(rc, rn, 0, 0);
    else
      ok = ramfs_write_file(rc, rn, src, size);
  }
  if (ok)
    sftp_root_note(canon, 0, size, 0);
  return ok;
}

static int sftp_remove_file(const char *canon)
{
  struct vfs_ctx *vfs = vfs_get_global();
  int ok = 0;
  if (!vfs)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    char rn[SFTP_MAX_PATH];
    if (!sftp_ram_name(fs_path, rn, sizeof(rn)))
      return 0;
    ok = ramfs_delete_file((struct ramfs_ctx *)m->fs_ctx, rn);
  }
  else if (m->fstype == VFS_FSTYPE_FAT)
  {
    /* fat12_delete_file always uses the boot-floppy ctx; only allow on "/". */
    if (!kstreq(m->mount_point, "/"))
      return 0;
    ok = fat12_delete_file(fs_path);
  }
  if (ok)
    sftp_root_note(canon, 0, 0, 1);
  return ok;
}

static int sftp_do_mkdir(const char *canon)
{
  struct vfs_ctx *vfs = vfs_get_global();
  int ok;
  if (!vfs)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  if (m->fstype != VFS_FSTYPE_FAT || !kstreq(m->mount_point, "/"))
    return 0;
  const char *p = fs_path;
  if (*p == '/')
    p++;
  ok = fat12_mkdir(p);
  if (ok)
    sftp_root_note(canon, 1, 0, 0);
  return ok;
}

static int sftp_do_rmdir(const char *canon)
{
  struct vfs_ctx *vfs = vfs_get_global();
  int ok;
  int is_dir = 0;
  uint32_t sz = 0;
  if (!vfs)
    return 0;
  if (kstreq(canon, "/") || kstreq(canon, "/tmp") || kstreq(canon, "/mnt"))
    return 0;
  if (!sftp_path_info(canon, &is_dir, &sz, 0) || !is_dir)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  if (m->fstype != VFS_FSTYPE_FAT || !kstreq(m->mount_point, "/"))
    return 0;
  ok = fat12_rmdir(fs_path);
  if (ok)
    sftp_root_note(canon, 1, 0, 1);
  return ok;
}

static int sftp_do_rename(const char *oldc, const char *newc, int overwrite)
{
  int old_dir = 0, new_exists = 0, new_dir = 0;
  uint32_t old_sz = 0, new_sz = 0;
  uint8_t *data = 0;
  uint32_t size = 0;
  int ok;
  if (kstreq(oldc, newc))
    return 1;
  if (!sftp_path_info(oldc, &old_dir, &old_sz, 0))
    return 0;
  if (old_dir)
    return 0; /* directory rename is not implemented */
  new_exists = sftp_path_info(newc, &new_dir, &new_sz, 0);
  if (new_exists)
  {
    if (!overwrite || new_dir)
      return 0;
    if (!sftp_remove_file(newc))
      return 0;
  }
  if (!sftp_load_file(oldc, &data, &size))
    return 0;
  ok = sftp_store_file(newc, data ? data : (const uint8_t *)"", size);
  if (data)
    kfree(data);
  if (!ok)
    return 0;
  if (!sftp_remove_file(oldc))
    return 0;
  return 1;
}

static int sftp_handle_resize(struct sftp_handle *h, uint32_t nsz)
{
  if (!h || h->is_dir)
    return 0;
  if (nsz > SFTP_MAX_FILE)
    return 0;
  if (nsz == 0)
  {
    if (h->data)
    {
      kfree(h->data);
      h->data = 0;
    }
    h->size = 0;
    h->cap = 0;
    h->load_tried = 1;
    h->dirty = 1;
    return 1;
  }
  if (!(h->flags & SSH_FXF_TRUNC) && !h->data && !h->load_tried)
    (void)sftp_ensure_loaded(h);
  if (nsz > h->cap)
  {
    uint8_t *nd = (uint8_t *)kmalloc(nsz);
    if (!nd)
      return 0;
    mem_set(nd, 0, nsz);
    if (h->data && h->size)
      mem_copy(nd, h->data, h->size < nsz ? h->size : nsz);
    if (h->data)
      kfree(h->data);
    h->data = nd;
    h->cap = nsz;
  }
  else if (h->data && nsz > h->size)
    mem_set(h->data + h->size, 0, nsz - h->size);
  h->size = nsz;
  h->dirty = 1;
  h->load_tried = 1;
  return 1;
}

static int sftp_truncate_path(const char *canon, uint32_t nsz)
{
  uint8_t *data = 0;
  uint32_t size = 0;
  int exists;
  int is_dir = 0;
  uint32_t dummy = 0;
  int ok;
  exists = sftp_path_info(canon, &is_dir, &dummy, 0);
  if (exists && is_dir)
    return 0;
  if (nsz == 0)
  {
    uint8_t z = 0;
    return sftp_store_file(canon, &z, 0);
  }
  if (exists)
    (void)sftp_load_file(canon, &data, &size);
  if (nsz > SFTP_MAX_FILE)
  {
    if (data)
      kfree(data);
    return 0;
  }
  {
    uint8_t *nd = (uint8_t *)kmalloc(nsz);
    if (!nd)
    {
      if (data)
        kfree(data);
      return 0;
    }
    mem_set(nd, 0, nsz);
    if (data && size)
      mem_copy(nd, data, size < nsz ? size : nsz);
    if (data)
      kfree(data);
    ok = sftp_store_file(canon, nd, nsz);
    kfree(nd);
    return ok;
  }
}

static void sftp_u32_dec(uint32_t v, char *out)
{
  char tmp[12];
  int n = 0;
  if (v == 0)
  {
    out[0] = '0';
    out[1] = '\0';
    return;
  }
  while (v && n < 10)
  {
    tmp[n++] = (char)('0' + (v % 10));
    v /= 10;
  }
  int i = 0;
  while (n--)
    out[i++] = tmp[n];
  out[i] = '\0';
}

static void sftp_longname(char *out, uint32_t cap, const struct sftp_dirent *e)
{
  /* ls -l style; OpenSSH uses this for the default `ls` display. */
  const char *mode = e->is_dir ? "drwxr-xr-x" : "-rw-r--r--";
  char sz[16];
  sftp_u32_dec(e->size, sz);
  uint32_t o = 0;
  const char *parts[8];
  parts[0] = mode;
  parts[1] = "    1 user     user ";
  parts[2] = sz;
  parts[3] = " Jan  1 00:00 ";
  parts[4] = e->name;
  parts[5] = 0;
  for (int pi = 0; parts[pi]; pi++)
  {
    const char *s = parts[pi];
    while (*s && o + 1 < cap)
      out[o++] = *s++;
  }
  out[o] = '\0';
}

static void sftp_send_name_one(struct ssh_connection *conn, uint32_t id,
                               const char *filename, int is_dir, uint32_t size)
{
  struct sftp_dirent e;
  mem_set((uint8_t *)&e, 0, sizeof(e));
  uint32_t k = 0;
  while (filename[k] && k + 1 < SFTP_NAME_MAX)
  {
    e.name[k] = filename[k];
    k++;
  }
  e.name[k] = '\0';
  e.is_dir = (uint8_t)is_dir;
  e.size = size;
  char longn[160];
  sftp_longname(longn, sizeof(longn), &e);
  uint32_t fnl = 0;
  while (filename[fnl])
    fnl++;
  uint32_t lnl = 0;
  while (longn[lnl])
    lnl++;
  uint32_t plen = 1 + 4 + 4 + 4 + fnl + 4 + lnl + SFTP_ATTR_BYTES;
  uint8_t buf[512];
  if (plen > sizeof(buf))
  {
    sftp_status(conn, id, SSH_FX_FAILURE, "nomem");
    return;
  }
  uint32_t o = 0;
  buf[o++] = SSH_FXP_NAME;
  sftp_wr_u32(buf + o, id);
  o += 4;
  sftp_wr_u32(buf + o, 1);
  o += 4;
  sftp_wr_u32(buf + o, fnl);
  o += 4;
  mem_copy(buf + o, filename, fnl);
  o += fnl;
  sftp_wr_u32(buf + o, lnl);
  o += 4;
  mem_copy(buf + o, longn, lnl);
  o += lnl;
  o += sftp_put_attrs(buf + o, is_dir, size, e.mtime);
  sftp_reply(conn, buf, o);
}

static void sftp_send_readdir(struct ssh_connection *conn, uint32_t id,
                              struct sftp_handle *h)
{
  if (h->eof_sent || h->dir_index >= h->dir_count)
  {
    h->eof_sent = 1;
    sftp_status(conn, id, SSH_FX_EOF, "end of dir");
    return;
  }
  /* Send remaining entries in one NAME packet (capped). Built in
   * sftp_pkt_scratch so we never kmalloc a PMM-sized NAME payload. */
  uint32_t remain = h->dir_count - h->dir_index;
  uint32_t batch = remain;
  if (batch > 16)
    batch = 16;
  uint32_t cap = sizeof(sftp_pkt_scratch) - 4u;
  uint8_t *buf = sftp_pkt_scratch + 4;
  uint32_t o = 0;
  buf[o++] = SSH_FXP_NAME;
  sftp_wr_u32(buf + o, id);
  o += 4;
  uint32_t count_off = o;
  sftp_wr_u32(buf + o, 0);
  o += 4;
  uint32_t sent = 0;
  for (uint32_t i = 0; i < batch; i++)
  {
    struct sftp_dirent *e = &h->dirents[h->dir_index + i];
    uint32_t fnl = 0;
    while (e->name[fnl])
      fnl++;
    char longn[160];
    sftp_longname(longn, sizeof(longn), e);
    uint32_t lnl = 0;
    while (longn[lnl])
      lnl++;
    if (o + 4 + fnl + 4 + lnl + SFTP_ATTR_BYTES + 8 > cap)
      break;
    sftp_wr_u32(buf + o, fnl);
    o += 4;
    mem_copy(buf + o, e->name, fnl);
    o += fnl;
    sftp_wr_u32(buf + o, lnl);
    o += 4;
    mem_copy(buf + o, longn, lnl);
    o += lnl;
    o += sftp_put_attrs(buf + o, e->is_dir, e->size, e->mtime);
    sent++;
  }
  sftp_wr_u32(buf + count_off, sent);
  h->dir_index += sent;
  log_writestring("DBG: readdir reply built sent=");
  log_write_u32(sent);
  log_writestring(" o=");
  log_write_u32(o);
  log_putchar('\n');
  sftp_reply(conn, buf, o);
  log_writestring("DBG: readdir sftp_reply returned\n");
}

static void sftp_on_packet(struct sftp_sess *s, const uint8_t *p, int len)
{
  struct ssh_connection *conn = s->conn;
  if (len < 1)
    return;
  uint8_t type = p[0];
  log_writestring("DBG: sftp pkt type=");
  log_write_u32(type);
  log_writestring(" len=");
  log_write_u32((uint32_t)len);
  log_putchar('\n');
  if (type == SSH_FXP_INIT)
  {
    uint8_t buf[160];
    uint32_t o = 0;
    buf[o++] = SSH_FXP_VERSION;
    sftp_wr_u32(buf + o, SFTP_VERSION);
    o += 4;
    o += sftp_put_str(buf + o, "posix-rename@openssh.com");
    o += sftp_put_str(buf + o, "1");
    o += sftp_put_str(buf + o, "fsync@openssh.com");
    o += sftp_put_str(buf + o, "1");
    o += sftp_put_str(buf + o, "statvfs@openssh.com");
    o += sftp_put_str(buf + o, "2");
    sftp_reply(conn, buf, o);
    return;
  }
  if (len < 5)
  {
    sftp_status(conn, 0, SSH_FX_BAD_MESSAGE, "short");
    return;
  }
  uint32_t id = sftp_rd_u32(p + 1);
  int off = 5;

  if (type == SSH_FXP_REALPATH || type == SSH_FXP_STAT || type == SSH_FXP_LSTAT ||
      type == SSH_FXP_REMOVE || type == SSH_FXP_RMDIR || type == SSH_FXP_OPENDIR)
  {
    char path[SFTP_MAX_PATH];
    if (!sftp_get_str(p, len, &off, path, sizeof(path)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "path");
      return;
    }
    char canon[SFTP_MAX_PATH];
    if (!sftp_canon(path, canon, sizeof(canon)))
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "path");
      return;
    }
    if (type == SSH_FXP_REALPATH)
    {
      int is_dir = 0;
      uint32_t sz = 0;
      if (!sftp_path_info(canon, &is_dir, &sz, 0))
      {
        /* Still return the canonical name so `cd`/`ls` of `/` works after
         * REALPATH("."); missing last component is reported on STAT. */
        is_dir = (canon[0] == '/' && canon[1] == '\0');
        sz = 0;
      }
      sftp_send_name_one(conn, id, canon, is_dir, sz);
      return;
    }
    if (type == SSH_FXP_STAT || type == SSH_FXP_LSTAT)
    {
      int is_dir = 0;
      uint32_t sz = 0;
      uint32_t mt = 0;
      if (!sftp_path_info(canon, &is_dir, &sz, &mt))
      {
        sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "no such file");
        return;
      }
      sftp_send_attrs(conn, id, is_dir, sz, mt);
      return;
    }
    if (type == SSH_FXP_REMOVE)
    {
      if (!sftp_remove_file(canon))
        sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "remove failed");
      else
        sftp_status(conn, id, SSH_FX_OK, "ok");
      return;
    }
    if (type == SSH_FXP_RMDIR)
    {
      if (!sftp_do_rmdir(canon))
        sftp_status(conn, id, SSH_FX_FAILURE, "rmdir failed");
      else
        sftp_status(conn, id, SSH_FX_OK, "ok");
      return;
    }
    if (type == SSH_FXP_OPENDIR)
    {
      int is_dir = 0;
      uint32_t sz = 0;
      if (!sftp_path_info(canon, &is_dir, &sz, 0) || !is_dir)
      {
        sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "not a directory");
        return;
      }
      struct sftp_handle *h = sftp_handle_alloc(s);
      if (!h)
      {
        sftp_status(conn, id, SSH_FX_FAILURE, "no handles");
        return;
      }
      sftp_path_copy(h->path, canon);
      h->is_dir = 1;
      if (!sftp_list_path(canon, h->dirents, SFTP_DIR_MAX, &h->dir_count))
      {
        sftp_handle_free(h);
        sftp_status(conn, id, SSH_FX_FAILURE, "list failed");
        return;
      }
      sftp_send_handle(conn, id, h->id);
      return;
    }
  }

  if (type == SSH_FXP_MKDIR)
  {
    char path[SFTP_MAX_PATH];
    if (!sftp_get_str(p, len, &off, path, sizeof(path)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "path");
      return;
    }
    sftp_skip_attrs(p, len, &off);
    char canon[SFTP_MAX_PATH];
    if (!sftp_canon(path, canon, sizeof(canon)) || !sftp_do_mkdir(canon))
      sftp_status(conn, id, SSH_FX_FAILURE, "mkdir failed");
    else
      sftp_status(conn, id, SSH_FX_OK, "ok");
    return;
  }

  if (type == SSH_FXP_SETSTAT)
  {
    char path[SFTP_MAX_PATH];
    struct sftp_attrs at;
    char canon[SFTP_MAX_PATH];
    int is_dir = 0;
    uint32_t sz = 0;
    if (!sftp_get_str(p, len, &off, path, sizeof(path)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "path");
      return;
    }
    if (!sftp_parse_attrs(p, len, &off, &at))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "attrs");
      return;
    }
    if (!sftp_canon(path, canon, sizeof(canon)))
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "path");
      return;
    }
    if (!sftp_path_info(canon, &is_dir, &sz, 0))
    {
      sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "no such file");
      return;
    }
    if (at.has_size && !is_dir)
    {
      if (!sftp_truncate_path(canon, at.size))
      {
        sftp_status(conn, id, SSH_FX_FAILURE, "truncate");
        return;
      }
    }
    sftp_status(conn, id, SSH_FX_OK, "ok");
    return;
  }

  if (type == SSH_FXP_OPEN)
  {
    char path[SFTP_MAX_PATH];
    if (!sftp_get_str(p, len, &off, path, sizeof(path)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "path");
      return;
    }
    if (off + 4 > len)
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "flags");
      return;
    }
    uint32_t flags = sftp_rd_u32(p + off);
    off += 4;
    sftp_skip_attrs(p, len, &off);
    char canon[SFTP_MAX_PATH];
    if (!sftp_canon(path, canon, sizeof(canon)))
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "path");
      return;
    }
    int exists = 0, is_dir = 0;
    uint32_t sz = 0;
    if (sftp_path_info(canon, &is_dir, &sz, 0))
      exists = 1;
    if (exists && is_dir)
    {
      sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "is a directory");
      return;
    }
    if ((flags & SSH_FXF_CREAT) && (flags & SSH_FXF_EXCL) && exists)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "exists");
      return;
    }
    if (!(flags & SSH_FXF_CREAT) && !exists)
    {
      sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "no such file");
      return;
    }
    struct sftp_handle *h = sftp_handle_alloc(s);
    if (!h)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "no handles");
      return;
    }
    sftp_path_copy(h->path, canon);
    h->flags = flags;
    h->is_dir = 0;
    h->load_tried = 0;
    /* Reply with HANDLE before any FAT cluster walk. OpenSSH prints
     * "Fetching ..." after STAT and then blocks on OPEN; loading the file
     * here wedged the guest inside CHANNEL_DATA so the HANDLE never went out. */
    h->mtime = SFTP_DEFAULT_MTIME;
    h->data = 0;
    h->size = exists ? sz : 0;
    h->cap = 0;
    if ((flags & SSH_FXF_TRUNC) || ((flags & SSH_FXF_CREAT) && !exists))
    {
      h->size = 0;
      h->dirty = 1;
      h->load_tried = 1;
    }
    if ((flags & SSH_FXF_CREAT) && !exists)
      sftp_root_note(canon, 0, 0, 0);
    sftp_send_handle(conn, id, h->id);
    return;
  }

  if (type == SSH_FXP_CLOSE)
  {
    uint32_t hid;
    if (!sftp_get_handle(p, len, &off, &hid))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "handle");
      return;
    }
    struct sftp_handle *h = sftp_handle_by_id(s, hid);
    if (!h)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
      return;
    }
    int ok = 1;
    if (!h->is_dir && h->dirty)
    {
      uint8_t dummy = 0;
      ok = sftp_store_file(h->path, h->data ? h->data : &dummy, h->size);
    }
    sftp_handle_free(h);
    sftp_status(conn, id, ok ? SSH_FX_OK : SSH_FX_FAILURE,
                ok ? "ok" : "write failed");
    return;
  }

  if (type == SSH_FXP_READDIR)
  {
    uint32_t hid;
    if (!sftp_get_handle(p, len, &off, &hid))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "handle");
      return;
    }
    struct sftp_handle *h = sftp_handle_by_id(s, hid);
    if (!h || !h->is_dir)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
      return;
    }
    sftp_send_readdir(conn, id, h);
    return;
  }

  if (type == SSH_FXP_FSTAT)
  {
    uint32_t hid;
    if (!sftp_get_handle(p, len, &off, &hid))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "handle");
      return;
    }
    struct sftp_handle *h = sftp_handle_by_id(s, hid);
    if (!h)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
      return;
    }
    sftp_send_attrs(conn, id, h->is_dir, h->size,
                    h->mtime ? h->mtime : SFTP_DEFAULT_MTIME);
    return;
  }

  if (type == SSH_FXP_FSETSTAT)
  {
    uint32_t hid;
    struct sftp_attrs at;
    struct sftp_handle *h;
    if (!sftp_get_handle(p, len, &off, &hid))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "handle");
      return;
    }
    if (!sftp_parse_attrs(p, len, &off, &at))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "attrs");
      return;
    }
    h = sftp_handle_by_id(s, hid);
    if (!h)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
      return;
    }
    if (at.has_size && !h->is_dir)
    {
      if (!sftp_handle_resize(h, at.size))
      {
        sftp_status(conn, id, SSH_FX_FAILURE, "truncate");
        return;
      }
    }
    if (at.mtime)
      h->mtime = at.mtime;
    sftp_status(conn, id, SSH_FX_OK, "ok");
    return;
  }

  if (type == SSH_FXP_READ)
  {
    uint32_t hid;
    if (!sftp_get_handle(p, len, &off, &hid) || off + 12 > len)
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "read");
      return;
    }
    uint32_t off_hi = sftp_rd_u32(p + off);
    uint32_t off_lo = sftp_rd_u32(p + off + 4);
    uint32_t want = sftp_rd_u32(p + off + 8);
    struct sftp_handle *h = sftp_handle_by_id(s, hid);
    if (!h || h->is_dir)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
      return;
    }
    if (!(h->flags & SSH_FXF_TRUNC) && !h->data)
      (void)sftp_ensure_loaded(h);
    if (off_hi != 0 || !h->data || off_lo >= h->size)
    {
      sftp_status(conn, id, SSH_FX_EOF, "eof");
      return;
    }
    uint32_t avail = h->size - off_lo;
    if (want > avail)
      want = avail;
    if (want > SFTP_DATA_MAX)
      want = SFTP_DATA_MAX;
    uint32_t plen = 1 + 4 + 4 + want;
    static uint8_t sftp_read_payload[SFTP_DATA_MAX + 16];
    if (plen > sizeof(sftp_read_payload))
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "nomem");
      return;
    }
    sftp_read_payload[0] = SSH_FXP_DATA;
    sftp_wr_u32(sftp_read_payload + 1, id);
    sftp_wr_u32(sftp_read_payload + 5, want);
    if (want && h->data)
      mem_copy(sftp_read_payload + 9, h->data + off_lo, want);
    sftp_reply(conn, sftp_read_payload, plen);
    return;
  }

  if (type == SSH_FXP_WRITE)
  {
    uint32_t hid;
    if (!sftp_get_handle(p, len, &off, &hid) || off + 8 + 4 > len)
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "write");
      return;
    }
    uint32_t off_hi = sftp_rd_u32(p + off);
    uint32_t off_lo = sftp_rd_u32(p + off + 4);
    off += 8;
    uint32_t n = sftp_rd_u32(p + off);
    off += 4;
    if (off_hi != 0 || n > 65536u || off + (int)n > len)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "write range");
      return;
    }
    struct sftp_handle *h = sftp_handle_by_id(s, hid);
    if (!h || h->is_dir || !(h->flags & SSH_FXF_WRITE))
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
      return;
    }
    if (h->flags & SSH_FXF_APPEND)
      off_lo = h->size;
    if (!(h->flags & SSH_FXF_TRUNC) && !h->data && !h->load_tried)
      (void)sftp_ensure_loaded(h);
    if ((h->flags & SSH_FXF_APPEND) && h->data)
      off_lo = h->size;
    uint32_t end = off_lo + n;
    if (end < off_lo || end > SFTP_MAX_FILE)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "too large");
      return;
    }
    if (end > h->cap)
    {
      uint32_t ncap = end;
      if (ncap < 64)
        ncap = 64;
      uint8_t *nd = (uint8_t *)kmalloc(ncap ? ncap : 1);
      if (!nd)
      {
        sftp_status(conn, id, SSH_FX_FAILURE, "nomem");
        return;
      }
      mem_set(nd, 0, ncap);
      if (h->data && h->size)
        mem_copy(nd, h->data, h->size);
      if (h->data)
        kfree(h->data);
      h->data = nd;
      h->cap = ncap;
    }
    if (n)
      mem_copy(h->data + off_lo, p + off, n);
    if (end > h->size)
      h->size = end;
    h->dirty = 1;
    sftp_status(conn, id, SSH_FX_OK, "ok");
    return;
  }

  if (type == SSH_FXP_RENAME)
  {
    char oldp[SFTP_MAX_PATH];
    char newp[SFTP_MAX_PATH];
    char oldc[SFTP_MAX_PATH];
    char newc[SFTP_MAX_PATH];
    if (!sftp_get_str(p, len, &off, oldp, sizeof(oldp)) ||
        !sftp_get_str(p, len, &off, newp, sizeof(newp)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "rename");
      return;
    }
    if (!sftp_canon(oldp, oldc, sizeof(oldc)) ||
        !sftp_canon(newp, newc, sizeof(newc)))
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "path");
      return;
    }
    if (!sftp_do_rename(oldc, newc, 0))
      sftp_status(conn, id, SSH_FX_FAILURE, "rename failed");
    else
      sftp_status(conn, id, SSH_FX_OK, "ok");
    return;
  }

  if (type == SSH_FXP_EXTENDED)
  {
    char ext[64];
    if (!sftp_get_str(p, len, &off, ext, sizeof(ext)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "ext");
      return;
    }
    if (kstreq(ext, "posix-rename@openssh.com"))
    {
      char oldp[SFTP_MAX_PATH];
      char newp[SFTP_MAX_PATH];
      char oldc[SFTP_MAX_PATH];
      char newc[SFTP_MAX_PATH];
      if (!sftp_get_str(p, len, &off, oldp, sizeof(oldp)) ||
          !sftp_get_str(p, len, &off, newp, sizeof(newp)))
      {
        sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "rename");
        return;
      }
      if (!sftp_canon(oldp, oldc, sizeof(oldc)) ||
          !sftp_canon(newp, newc, sizeof(newc)))
      {
        sftp_status(conn, id, SSH_FX_FAILURE, "path");
        return;
      }
      if (!sftp_do_rename(oldc, newc, 1))
        sftp_status(conn, id, SSH_FX_FAILURE, "rename failed");
      else
        sftp_status(conn, id, SSH_FX_OK, "ok");
      return;
    }
    if (kstreq(ext, "fsync@openssh.com"))
    {
      uint32_t hid;
      struct sftp_handle *h;
      int ok = 1;
      if (!sftp_get_handle(p, len, &off, &hid))
      {
        sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "handle");
        return;
      }
      h = sftp_handle_by_id(s, hid);
      if (!h)
      {
        sftp_status(conn, id, SSH_FX_FAILURE, "bad handle");
        return;
      }
      if (!h->is_dir && h->dirty)
      {
        uint8_t dummy = 0;
        ok = sftp_store_file(h->path, h->data ? h->data : &dummy, h->size);
        if (ok)
          h->dirty = 0;
      }
      sftp_status(conn, id, ok ? SSH_FX_OK : SSH_FX_FAILURE,
                  ok ? "ok" : "fsync failed");
      return;
    }
    if (kstreq(ext, "statvfs@openssh.com"))
    {
      /* draft-ietf-secsh-filexfer + OpenSSH statvfs@openssh.com v2. */
      uint8_t buf[1 + 4 + 11 * 8];
      uint32_t o = 0;
      buf[o++] = SSH_FXP_EXTENDED_REPLY;
      sftp_wr_u32(buf + o, id);
      o += 4;
      /* bsize, frsize */
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 512);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 512);
      o += 8;
      /* blocks, bfree, bavail (1.44MB floppy-ish) */
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 2880);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 2000);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 2000);
      o += 8;
      /* files, ffree, favail */
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 224);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 100);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 100);
      o += 8;
      /* fsid, flag, namemax */
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 1);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 0);
      o += 8;
      sftp_wr_u32(buf + o, 0);
      sftp_wr_u32(buf + o + 4, 255);
      o += 8;
      sftp_reply(conn, buf, o);
      return;
    }
    sftp_status(conn, id, SSH_FX_OP_UNSUPPORTED, "unsupported");
    return;
  }

  if (type == SSH_FXP_SYMLINK || type == SSH_FXP_READLINK)
  {
    sftp_status(conn, id, SSH_FX_OP_UNSUPPORTED, "unsupported");
    return;
  }

  sftp_status(conn, id, SSH_FX_OP_UNSUPPORTED, "unknown");
}

int sftp_session_init(struct ssh_connection *conn)
{
  if (!conn)
    return 0;
  sftp_session_close(conn);
  struct sftp_sess *s = 0;
  int slot = -1;
  for (int i = 0; i < SFTP_MAX_SESSIONS; i++)
  {
    if (!sftp_sessions[i].conn)
    {
      s = &sftp_sessions[i];
      slot = i;
      break;
    }
  }
  if (!s)
    return 0;
  for (int i = 0; i < SFTP_MAX_HANDLES; i++)
    sftp_handle_free(&s->handles[i]);
  s->rx = s->rx_store;
  s->rx_cap = SFTP_RX_MAX;
  s->rx_len = 0;
  s->next_id = 1;
  s->conn = conn;
  conn->sftp_active = 1;
  (void)slot;
  return 1;
}

void sftp_session_close(struct ssh_connection *conn)
{
  if (!conn)
    return;
  struct sftp_sess *s = sftp_find(conn);
  if (s)
    sftp_sess_reset(s);
  conn->sftp_active = 0;
}

void sftp_feed(struct ssh_connection *conn, const uint8_t *data, uint32_t len)
{
  struct sftp_sess *s = sftp_find(conn);
  if (!s || !s->rx || !data || len == 0)
    return;
  uint32_t pos = 0;
  while (pos < len)
  {
    uint32_t room = s->rx_cap - s->rx_len;
    uint32_t chunk = len - pos;
    if (chunk > room)
      chunk = room;
    if (chunk == 0)
    {
      log_writestring("[SFTP] rx overflow, dropping\n");
      s->rx_len = 0;
      return;
    }
    mem_copy(s->rx + s->rx_len, data + pos, chunk);
    s->rx_len += chunk;
    pos += chunk;
  }
}

void sftp_process_pending(struct ssh_connection *conn)
{
  struct sftp_sess *s;
  if (!conn || !conn->sftp_active || sftp_dispatching)
    return;
  s = sftp_find(conn);
  if (!s || !s->rx)
    return;

  /* Same pattern as ssh_flush_pending_shell_commands: drop processing so
   * nested tcp_input can append CHANNEL_DATA / WINDOW_ADJUST while FAT I/O
   * and CHANNEL_DATA TX run. */
  uint8_t saved_processing = conn->processing;
  sftp_dispatching = 1;
  conn->processing = 0;

  while (s->rx_len >= 4)
  {
    uint32_t pktlen = sftp_rd_u32(s->rx);
    uint32_t used;
    uint32_t rest;
    if (pktlen < 1 || pktlen > s->rx_cap - 4)
    {
      log_writestring("[SFTP] bad packet length ");
      log_write_u32(pktlen);
      log_putchar('\n');
      s->rx_len = 0;
      break;
    }
    if (s->rx_len < 4 + pktlen)
      break;
    if (pktlen > sizeof(sftp_pkt_in))
    {
      s->rx_len = 0;
      break;
    }
    mem_copy(sftp_pkt_in, s->rx + 4, pktlen);
    used = 4 + pktlen;
    rest = s->rx_len - used;
    if (rest)
      mem_copy(s->rx, s->rx + used, rest);
    s->rx_len = rest;
    sftp_on_packet(s, sftp_pkt_in, (int)pktlen);
  }

  conn->processing = saved_processing;
  sftp_dispatching = 0;
}
