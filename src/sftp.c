#include "sftp.h"
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
#define SFTP_MAX_HANDLES 8
#define SFTP_MAX_PATH 256
#define SFTP_RX_MAX 32768u
#define SFTP_MAX_FILE 262144u
#define SFTP_DIR_MAX 64
#define SFTP_NAME_MAX 80
#define SFTP_DATA_MAX 8192u

struct sftp_dirent
{
  char name[SFTP_NAME_MAX];
  uint8_t is_dir;
  uint32_t size;
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
  char path[SFTP_MAX_PATH];
  uint8_t *data;
  uint32_t size;
  uint32_t cap;
  uint32_t dir_count;
  uint32_t dir_index;
  struct sftp_dirent *dirents;
};

struct sftp_sess
{
  struct ssh_connection *conn;
  uint8_t *rx;
  uint32_t rx_len;
  uint32_t rx_cap;
  uint32_t next_id;
  struct sftp_handle handles[SFTP_MAX_HANDLES];
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

static int sftp_skip_attrs(const uint8_t *p, int len, int *off)
{
  if (*off + 4 > len)
    return 0;
  uint32_t flags = sftp_rd_u32(p + *off);
  *off += 4;
  if (flags & SSH_FILEXFER_ATTR_SIZE)
  {
    if (*off + 8 > len)
      return 0;
    *off += 8;
  }
  if (flags & SSH_FILEXFER_ATTR_UIDGID)
  {
    if (*off + 8 > len)
      return 0;
    *off += 8;
  }
  if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
  {
    if (*off + 4 > len)
      return 0;
    *off += 4;
  }
  if (flags & SSH_FILEXFER_ATTR_ACMODTIME)
  {
    if (*off + 8 > len)
      return 0;
    *off += 8;
  }
  if (flags & SSH_FILEXFER_ATTR_EXTENDED)
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
  return 1;
}

static uint32_t sftp_attr_perms(int is_dir)
{
  return is_dir ? (uint32_t)(S_IFDIR | 0755) : (uint32_t)(S_IFREG | 0644);
}

static uint32_t sftp_put_attrs(uint8_t *d, int is_dir, uint32_t size)
{
  uint32_t flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
  sftp_wr_u32(d, flags);
  sftp_wr_u64(d + 4, size);
  sftp_wr_u32(d + 12, sftp_attr_perms(is_dir));
  return 16;
}

static void sftp_reply(struct ssh_connection *conn, const uint8_t *payload,
                       uint32_t plen)
{
  uint8_t small[512];
  uint8_t *pkt;
  if (4u + plen <= sizeof(small))
    pkt = small;
  else
  {
    pkt = (uint8_t *)kmalloc(4u + plen);
    if (!pkt)
      return;
  }
  sftp_wr_u32(pkt, plen);
  if (plen)
    mem_copy(pkt + 4, payload, plen);
  ssh_channel_write(conn, pkt, 4u + plen);
  if (pkt != small)
    kfree(pkt);
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
                            uint32_t size)
{
  uint8_t buf[24];
  buf[0] = SSH_FXP_ATTRS;
  sftp_wr_u32(buf + 1, id);
  uint32_t n = sftp_put_attrs(buf + 5, is_dir, size);
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
  if (h->dirents)
  {
    kfree(h->dirents);
    h->dirents = 0;
  }
  mem_set((uint8_t *)h, 0, sizeof(*h));
}

static void sftp_sess_reset(struct sftp_sess *s)
{
  if (!s)
    return;
  if (s->rx)
  {
    kfree(s->rx);
    s->rx = 0;
  }
  for (int i = 0; i < SFTP_MAX_HANDLES; i++)
    sftp_handle_free(&s->handles[i]);
  mem_set((uint8_t *)s, 0, sizeof(*s));
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

static int sftp_fat_list(fat12_ctx *ctx, const char *fs_path,
                         struct sftp_dirent *ents, uint32_t max,
                         uint32_t *out_n)
{
  fat12_reload(ctx);
  uint8_t *dir_buf = 0;
  uint32_t dir_bytes = 0;
  int ok = 0;
  const char *p = fs_path ? fs_path : "/";
  if (p[0] == '\0' || (p[0] == '/' && p[1] == '\0'))
    ok = fat12_read_root_dir(ctx, &dir_buf, &dir_bytes);
  else
  {
    int dok = 0;
    const char *rp = p;
    if (*rp == '/')
      rp++;
    uint16_t cluster = fat12_resolve_dir(ctx, 0, rp, &dok);
    if (dok)
      ok = (cluster == 0) ? fat12_read_root_dir(ctx, &dir_buf, &dir_bytes)
                          : fat12_read_dir_cluster(ctx, cluster, &dir_buf,
                                                   &dir_bytes);
  }
  if (!ok || !dir_buf)
  {
    if (dir_buf)
      kfree(dir_buf);
    return 0;
  }
  uint32_t n = 0;
  uint32_t entries = dir_bytes / 32u;
  for (uint32_t i = 0; i < entries && n < max; i++)
  {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    if (e->attr == FAT_ATTR_LFN)
      continue;
    char formatted[256];
    fat12_display_name(dir_buf, i * 32u, formatted, sizeof(formatted));
    if (formatted[0] == '\0' || sftp_is_dot_name(formatted))
      continue;
    uint32_t k = 0;
    while (formatted[k] && k + 1 < SFTP_NAME_MAX)
    {
      ents[n].name[k] = formatted[k];
      k++;
    }
    ents[n].name[k] = '\0';
    ents[n].is_dir = (e->attr & 0x10) ? 1 : 0;
    ents[n].size = e->size;
    n++;
  }
  kfree(dir_buf);
  *out_n = n;
  return 1;
}

static int sftp_fat_stat(fat12_ctx *ctx, const char *fs_path, int *is_dir,
                         uint32_t *size)
{
  fat12_reload(ctx);
  const char *p = fs_path ? fs_path : "/";
  if (p[0] == '\0' || (p[0] == '/' && p[1] == '\0'))
  {
    *is_dir = 1;
    *size = 0;
    return 1;
  }
  int dok = 0;
  const char *rp = p;
  if (*rp == '/')
    rp++;
  fat12_resolve_dir(ctx, 0, rp, &dok);
  if (dok)
  {
    *is_dir = 1;
    *size = 0;
    return 1;
  }
  /* Look up in parent directory. */
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
    if (parent[1] == '\0')
    {
      /* already "/" */
    }
  }
  struct sftp_dirent ents[SFTP_DIR_MAX];
  uint32_t n = 0;
  if (!sftp_fat_list(ctx, parent, ents, SFTP_DIR_MAX, &n))
    return 0;
  for (uint32_t i = 0; i < n; i++)
  {
    if (sftp_name_eq_ci(ents[i].name, name))
    {
      *is_dir = ents[i].is_dir;
      *size = ents[i].size;
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

static int sftp_path_info(const char *canon, int *is_dir, uint32_t *size)
{
  struct vfs_ctx *vfs = vfs_get_global();
  if (!vfs)
    return 0;
  if (canon[0] == '/' && canon[1] == '\0')
  {
    *is_dir = 1;
    *size = 0;
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
    return 1;
  }
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    return sftp_fat_stat((fat12_ctx *)m->fs_ctx, fs_path, is_dir, size);
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
    return 1;
  }
  return 0;
}

static int sftp_list_path(const char *canon, struct sftp_dirent **out_ents,
                          uint32_t *out_n)
{
  struct vfs_ctx *vfs = vfs_get_global();
  if (!vfs)
    return 0;
  int mount_id = -1;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(vfs, canon, &mount_id, fs_path))
    return 0;
  struct vfs_mount *m = &vfs->mounts[mount_id];
  struct sftp_dirent *ents =
      (struct sftp_dirent *)kmalloc(sizeof(struct sftp_dirent) * SFTP_DIR_MAX);
  if (!ents)
    return 0;
  mem_set((uint8_t *)ents, 0, sizeof(struct sftp_dirent) * SFTP_DIR_MAX);
  uint32_t n = 0;
  int ok = 0;
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    ok = sftp_fat_list((fat12_ctx *)m->fs_ctx, fs_path, ents, SFTP_DIR_MAX, &n);
  }
  else if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    struct ramfs_ctx *rc = (struct ramfs_ctx *)m->fs_ctx;
    char **names = 0;
    uint32_t count = 0;
    if (ramfs_list_files(rc, &names, &count))
    {
      ok = 1;
      for (uint32_t i = 0; i < count && n < SFTP_DIR_MAX; i++)
      {
        const char *nm = names[i];
        while (*nm == '/')
          nm++;
        uint32_t k = 0;
        while (nm[k] && k + 1 < SFTP_NAME_MAX)
        {
          ents[n].name[k] = nm[k];
          k++;
        }
        ents[n].name[k] = '\0';
        ents[n].is_dir = 0;
        ramfs_get_file_size(rc, names[i], &ents[n].size);
        if (!ents[n].size)
          ramfs_get_file_size(rc, nm, &ents[n].size);
        n++;
      }
      if (count > 0 && names)
      {
        kfree(names[0]);
        kfree(names);
      }
    }
  }
  if (!ok)
  {
    kfree(ents);
    return 0;
  }
  *out_ents = ents;
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
    /* Do not fat12_init() a ~17KB ctx on the SSH stack, and do not fat12_reload()
     * here: both have wedged OpenSSH `get` while CHANNEL_DATA was still being
     * handled. Use the long-lived mount ctx with a hop-capped read. */
    fat12_ctx *ctx = (fat12_ctx *)m->fs_ctx;
    if (kstreq(m->mount_point, "/"))
    {
      extern fat12_ctx fat_global_ctx;
      ctx = &fat_global_ctx;
    }
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
  {
    log_writestring("[SFTP] load failed ");
    log_writestring(h->path);
    log_putchar('\n');
    return 0;
  }
  h->data = data;
  h->size = size;
  h->cap = size;
  log_writestring("[SFTP] loaded ");
  log_writestring(h->path);
  log_writestring(" bytes=");
  log_write_u32(size);
  log_putchar('\n');
  return 1;
}

static int sftp_store_file(const char *canon, const uint8_t *data, uint32_t size)
{
  struct vfs_ctx *vfs = vfs_get_global();
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
      return fat12_write_file(fs_path, src, size);
    fat12_ctx *ctx = (fat12_ctx *)m->fs_ctx;
    fat12_reload(ctx);
    return fat12_write_file_ex(ctx, fs_path, src, size);
  }
  if (m->fstype == VFS_FSTYPE_RAMFS)
  {
    char rn[SFTP_MAX_PATH];
    if (!sftp_ram_name(fs_path, rn, sizeof(rn)))
      return 0;
    struct ramfs_ctx *rc = (struct ramfs_ctx *)m->fs_ctx;
    if (size == 0)
      return ramfs_write_file(rc, rn, &dummy, 0) || ramfs_create_file(rc, rn, 0, 0);
    return ramfs_write_file(rc, rn, src, size);
  }
  return 0;
}

static int sftp_remove_file(const char *canon)
{
  struct vfs_ctx *vfs = vfs_get_global();
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
    return ramfs_delete_file((struct ramfs_ctx *)m->fs_ctx, rn);
  }
  if (m->fstype == VFS_FSTYPE_FAT)
  {
    /* fat12_delete_file always uses the boot-floppy ctx; only allow on "/". */
    if (!kstreq(m->mount_point, "/"))
      return 0;
    return fat12_delete_file(fs_path);
  }
  return 0;
}

static int sftp_do_mkdir(const char *canon)
{
  struct vfs_ctx *vfs = vfs_get_global();
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
  return fat12_mkdir(p);
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
  uint32_t plen = 1 + 4 + 4 + 4 + fnl + 4 + lnl + 16;
  uint8_t *buf = (uint8_t *)kmalloc(plen);
  if (!buf)
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
  o += sftp_put_attrs(buf + o, is_dir, size);
  sftp_reply(conn, buf, o);
  kfree(buf);
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
  /* Send remaining entries in one NAME packet (capped). */
  uint32_t remain = h->dir_count - h->dir_index;
  uint32_t batch = remain;
  if (batch > 16)
    batch = 16;
  uint32_t cap = 1 + 4 + 4 + batch * (4 + SFTP_NAME_MAX + 4 + 160 + 16) + 32;
  uint8_t *buf = (uint8_t *)kmalloc(cap);
  if (!buf)
  {
    sftp_status(conn, id, SSH_FX_FAILURE, "nomem");
    return;
  }
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
    if (o + 4 + fnl + 4 + lnl + 16 + 8 > cap)
      break;
    sftp_wr_u32(buf + o, fnl);
    o += 4;
    mem_copy(buf + o, e->name, fnl);
    o += fnl;
    sftp_wr_u32(buf + o, lnl);
    o += 4;
    mem_copy(buf + o, longn, lnl);
    o += lnl;
    o += sftp_put_attrs(buf + o, e->is_dir, e->size);
    sent++;
  }
  sftp_wr_u32(buf + count_off, sent);
  h->dir_index += sent;
  sftp_reply(conn, buf, o);
  kfree(buf);
}

static void sftp_on_packet(struct sftp_sess *s, const uint8_t *p, int len)
{
  struct ssh_connection *conn = s->conn;
  if (len < 1)
    return;
  uint8_t type = p[0];
  if (type != SSH_FXP_INIT)
  {
    log_writestring("[SFTP] rx type=");
    log_write_u32(type);
    if (len >= 5)
    {
      log_writestring(" id=");
      log_write_u32(sftp_rd_u32(p + 1));
    }
    log_putchar('\n');
  }
  if (type == SSH_FXP_INIT)
  {
    uint8_t buf[5];
    buf[0] = SSH_FXP_VERSION;
    sftp_wr_u32(buf + 1, SFTP_VERSION);
    sftp_reply(conn, buf, 5);
    log_writestring("[SFTP] INIT -> VERSION 3\n");
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
      if (!sftp_path_info(canon, &is_dir, &sz))
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
      if (!sftp_path_info(canon, &is_dir, &sz))
      {
        sftp_status(conn, id, SSH_FX_NO_SUCH_FILE, "no such file");
        return;
      }
      sftp_send_attrs(conn, id, is_dir, sz);
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
      sftp_status(conn, id, SSH_FX_OP_UNSUPPORTED, "rmdir");
      return;
    }
    if (type == SSH_FXP_OPENDIR)
    {
      int is_dir = 0;
      uint32_t sz = 0;
      if (!sftp_path_info(canon, &is_dir, &sz) || !is_dir)
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
      if (!sftp_list_path(canon, &h->dirents, &h->dir_count))
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
    if (!sftp_get_str(p, len, &off, path, sizeof(path)))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "path");
      return;
    }
    sftp_skip_attrs(p, len, &off);
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
    if (sftp_path_info(canon, &is_dir, &sz))
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
    h->data = 0;
    h->size = exists ? sz : 0;
    h->cap = 0;
    if ((flags & SSH_FXF_TRUNC) || ((flags & SSH_FXF_CREAT) && !exists))
    {
      h->size = 0;
      h->dirty = 1;
      h->load_tried = 1; /* truncated/new: do not populate from disk */
    }
    log_writestring("[SFTP] OPEN ");
    log_writestring(canon);
    log_writestring(" flags=");
    log_write_u32(flags);
    log_writestring(" size=");
    log_write_u32(h->size);
    log_putchar('\n');
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
    if (!h->is_dir && !h->data && !(h->flags & SSH_FXF_TRUNC))
      (void)sftp_ensure_loaded(h);
    sftp_send_attrs(conn, id, h->is_dir, h->size);
    return;
  }

  if (type == SSH_FXP_FSETSTAT)
  {
    uint32_t hid;
    if (!sftp_get_handle(p, len, &off, &hid))
    {
      sftp_status(conn, id, SSH_FX_BAD_MESSAGE, "handle");
      return;
    }
    (void)sftp_handle_by_id(s, hid);
    sftp_skip_attrs(p, len, &off);
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
    uint8_t *buf = (uint8_t *)kmalloc(plen);
    if (!buf)
    {
      sftp_status(conn, id, SSH_FX_FAILURE, "nomem");
      return;
    }
    buf[0] = SSH_FXP_DATA;
    sftp_wr_u32(buf + 1, id);
    sftp_wr_u32(buf + 5, want);
    if (want && h->data)
      mem_copy(buf + 9, h->data + off_lo, want);
    sftp_reply(conn, buf, plen);
    kfree(buf);
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
    if (!(h->flags & SSH_FXF_TRUNC) && !h->data && !h->load_tried)
      (void)sftp_ensure_loaded(h);
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

  if (type == SSH_FXP_RENAME || type == SSH_FXP_SYMLINK ||
      type == SSH_FXP_READLINK || type == SSH_FXP_EXTENDED)
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
  for (int i = 0; i < SFTP_MAX_SESSIONS; i++)
  {
    if (!sftp_sessions[i].conn)
    {
      s = &sftp_sessions[i];
      break;
    }
  }
  if (!s)
    return 0;
  mem_set((uint8_t *)s, 0, sizeof(*s));
  s->rx = (uint8_t *)kmalloc(SFTP_RX_MAX);
  if (!s->rx)
    return 0;
  s->conn = conn;
  s->rx_cap = SFTP_RX_MAX;
  s->rx_len = 0;
  s->next_id = 1;
  conn->sftp_active = 1;
  log_writestring("[SFTP] session started\n");
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
    while (s->rx_len >= 4)
    {
      uint32_t pktlen = sftp_rd_u32(s->rx);
      if (pktlen < 1 || pktlen > s->rx_cap - 4)
      {
        log_writestring("[SFTP] bad packet length ");
        log_write_u32(pktlen);
        log_putchar('\n');
        s->rx_len = 0;
        return;
      }
      if (s->rx_len < 4 + pktlen)
        break;
      sftp_on_packet(s, s->rx + 4, (int)pktlen);
      uint32_t used = 4 + pktlen;
      uint32_t rest = s->rx_len - used;
      if (rest)
        mem_copy(s->rx, s->rx + used, rest);
      s->rx_len = rest;
    }
  }
}
