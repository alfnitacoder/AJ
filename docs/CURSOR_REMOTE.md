# Cursor Remote-SSH into AJOS

AJOS is a **32-bit hobby kernel** with no Linux userspace. Cursor / VS Code
Remote-SSH installs a **host-native Node `cursor-server` binary** on the SSH
target. **That binary cannot run inside the guest.** This tree does not port
Node, glibc, or cursor-server into AJOS.

The supported UX is a **host-side gateway** on the same machine as QEMU
(your laptop):

| Surface | Where it actually runs |
| --- | --- |
| Cursor window / language features | `cursor-server` on **macOS or Linux** |
| Files in the explorer | **sshfs** mount of the AJOS VFS (`sftp` to the guest) |
| Integrated terminal | `ssh -p 9022 user@127.0.0.1` into the **guest shell** |

Connect to Host **`ajos`** SSHes into that gateway, not into QEMU’s port 22.

```
Laptop (OpenSSH + sshfs + Cursor)
  │
  ├─ ssh Host ajos  →  127.0.0.1:22229  (gateway sshd, your user)
  │                      └─ cursor-server lives in ~/.cursor-server
  │                      └─ Open Folder = ~/.ajos-cursor-remote/mnt
  │
  └─ sshfs + guest terminal →  127.0.0.1:9022  (QEMU hostfwd → guest :22)
                               user / pass
```

## One-command setup

1. Boot the guest with serial logged to a file (stdio serial can stall SSH):

   ```sh
   make run-console-file
   # wait for: [SSHD] Server started on port 22
   ```

2. In another terminal, from the repo root:

   ```sh
   make cursor-remote
   ```

   This runs `tools/ajos-cursor-remote/setup.sh`, which:

   - sshfs-mounts `user@127.0.0.1:9022:/` at `~/.ajos-cursor-remote/mnt`
   - starts a **user-mode** `sshd` on `127.0.0.1:22229`
   - writes `Host ajos` and `Include`s it from `~/.ssh/config`
   - generates a **local** ed25519 key (not a production secret; never commit it)

3. In Cursor: **Command Palette → “Remote-SSH: Connect to Host” → `ajos`**.
   Open folder `~/.ajos-cursor-remote/mnt` (or the workspace file printed by
   setup). The default terminal profile runs the guest shell.

Stop the gateway and unmount:

```sh
make cursor-remote-stop
```

### Guest account

| | |
| --- | --- |
| User | `user` |
| Password | `pass` |
| Guest listen | `:22` |
| QEMU hostfwd | `${HOST_SSH_PORT:-9022}` → `10.0.2.15:22` |

`sshpass` is used so setup/tests are non-interactive. You can SSH by hand:

```sh
ssh -p 9022 -o StrictHostKeyChecking=no user@127.0.0.1
# password: pass
```

Or `./tools/ajos-cursor-remote/guest-ssh.sh`.

## sshfs without Cursor

```sh
mkdir -p ~/ajos-mnt
echo pass | sshfs -o port=9022,password_stdin,reconnect,idmap=user \
  user@127.0.0.1:/ ~/ajos-mnt
ls ~/ajos-mnt
# README.TXT and the rest of the FAT/VFS tree
fusermount3 -u ~/ajos-mnt   # Linux; macOS: umount ~/ajos-mnt
```

Smoke test (guest must already be up):

```sh
./tools/ajos-cursor-remote/test-sshfs.sh
./test_sftp.sh
```

FAT 8.3 names: `hello.txt` is stored with a VFAT LFN when the name is not
already 8.3 uppercase, so a mount can round-trip that name. Directory
`mkdir` still uses 8.3 (`FOO` not `foo`). Prefer `/tmp` (ramfs) for
editor temp files and mixed-case names.

File size cap for SFTP I/O is 256 KiB. Do not copy `cursor-server` onto the
mount.

## Another machine

The gateway is meant for **Cursor and QEMU on the same laptop**. To work
from a second computer:

1. On the laptop, run `make run-console-file` and `make cursor-remote`.
2. From the other machine, SSH to the laptop (normal user SSH), then in
   Cursor use Remote-SSH to **the laptop** and open
   `~/.ajos-cursor-remote/mnt` — **or** tunnel both ports:

   ```sh
   ssh -L 22229:127.0.0.1:22229 -L 9022:127.0.0.1:9022 laptop
   ```

   Point `Host ajos` at your local 22229 (same snippet, different HostName if
   needed). Guest password remains `pass` on 9022.

Do not expose 9022 or 22229 on a public interface; both are test services.

## Why not Remote-SSH directly to port 9022?

Cursor would try to unpack and exec `cursor-server` **inside AJOS**. The
guest has no POSIX process model for that binary, no 64-bit userspace, and
no glibc. Connecting to `user@127.0.0.1:9022` is correct for a **shell** or
**sftp/sshfs**, not for Remote-SSH.

## Limitations

- Gateway sshd binds **loopback only**.
- sshfs needs FUSE (Linux) or macFUSE (macOS). Some VMs have `/dev/fuse`
  but still reject mounts; use `test_sftp.sh` there and sshfs on the laptop.
- Guest SFTP is v3 plus OpenSSH `posix-rename@openssh.com`,
  `fsync@openssh.com`, and `statvfs@openssh.com`. No symlinks.
- Directory rename is not implemented. Empty FAT `rmdir` is.
- Do not install Cursor server onto the sshfs mount (FAT/ramfs cannot hold
  it). Server path stays `~/.cursor-server` on the host disk.
