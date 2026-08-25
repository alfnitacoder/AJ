#ifndef SFTP_H
#define SFTP_H

#include <stdint.h>

struct ssh_connection;

/* RFC 4254 "subsystem" name "sftp" — draft-ietf-secsh-filexfer-02 (v3).
 * Tuned for sshfs: REALPATH, STAT/LSTAT/FSTAT (uid/gid/mode/mtime),
 * OPENDIR/READDIR including "."/"..", OPEN/READ/WRITE/CLOSE (creat/trunc/
 * append + fsync@openssh.com), MKDIR/RMDIR, REMOVE, RENAME /
 * posix-rename@openssh.com, SETSTAT/FSETSTAT size. I/O runs from
 * sftp_process_pending with conn->processing cleared (no kmalloc on the
 * SSH RX path). */
/* Copy the boot FAT root while BIOS disk is safe (before SSH RX). */
void sftp_cache_boot_root(void);
int sftp_session_init(struct ssh_connection *conn);
void sftp_session_close(struct ssh_connection *conn);
/* Append channel bytes only. Do not parse or reply here — that runs from
 * sftp_process_pending after the current SSH record is consumed. */
void sftp_feed(struct ssh_connection *conn, const uint8_t *data, uint32_t len);
/* Run complete SFTP packets with conn->processing cleared (FAT / TX). */
void sftp_process_pending(struct ssh_connection *conn);

#endif /* SFTP_H */
