# Developing for AJOS with Cursor (local) + guest (QEMU)

Cursor Remote-SSH cannot connect to AJOS: its bootstrap needs bash/wget/tar/Node
and the cursor-server is a Linux-x64 binary — AJOS is an i386 hobby kernel.
The SSH transport itself WORKS from Cursor (handshake, password auth, exec all
verified 2026-08-28); it dies at "Unknown command: bash". Use the local-bridge
workflow below instead.

## The bridge: tools/ajos_dev.sh

Edit files locally in Cursor (e.g. /Users/ageorge/AJOS/www/, examples/), then:

```sh
tools/ajos_dev.sh push myfile.html /tmp/myfile.html   # upload
tools/ajos_dev.sh pull /tmp/myfile.html local_copy    # download
tools/ajos_dev.sh run "ls /tmp"                       # run command on guest
tools/ajos_dev.sh sync ./mysite /tmp/mysite           # upload a directory
tools/ajos_dev.sh url                                 # preview URL
```

Credentials: user/pass on 127.0.0.1:9022 (SSH), :9080 (HTTP preview).

## Current limits (as of 2026-08-28)

1. FS visibility: SFTP-written files are visible to SFTP but NOT to the guest
   shell (cat/ls) or the HTTP server (which reads var/www/*.html from FAT via
   fat12_read_file_to_ram). Root cause is filesystem-layer (subsystem mount/
   cache incoherence; the fat12 root snapshot is taken at boot). Until fixed:
   - /tmp (ramfs) SFTP round-trips work perfectly (use for payloads)
   - serving NEW html requires the FS fix, or a rebuilt image (bake files into
     data.img / var/www before `make` + restart)
2. Connection churn can trip auth flakiness / slot wedging; `sshd stop` +
   `sshd start` on the serial console (build/ttyin.fifo) clears it.
3. KEX is slow (~2-25 s per connection).
