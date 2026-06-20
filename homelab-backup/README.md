# homelab-backup

Snapshot important configuration off one or more hosts over SSH into a single
timestamped, **AES-256-GCM-encrypted** archive — and restore it. Disaster
insurance for a homelab whose nodes are awkward to reach. **Zero dependencies.**

The archive is `gzip(tar)` of every host's files under a per-host directory,
sealed with AES-256-GCM. The key is PBKDF2-HMAC-SHA256(passphrase, salt),
hand-rolled on the standard library. A wrong passphrase fails the GCM
authentication tag with a clear error.

## Build

```sh
go build -o homelab-backup .
```

## Usage

```sh
homelab-backup backup  [-c backup.json] [-passfile F]
homelab-backup list    <archive> [-passfile F]
homelab-backup restore <archive> [-o DIR] [-passfile F]
homelab-backup init                       # write a starter backup.json
```

Passphrase resolution: `-passfile`, else `$HLBK_PASSPHRASE`, else an interactive
no-echo prompt (`backup` confirms it twice). Remote reads use `sudo tar`, so the
SSH user needs passwordless sudo where the files are root-only.

## Config (`backup.json`)

```json
{
  "ssh_key": "~/.ssh/id_ed25519",
  "out_dir": ".",
  "sources": [
    { "name": "server1", "ssh": "user@192.168.1.10",
      "paths": ["/etc/server1-panel", "/etc/nftables.conf"] },
    { "name": "pi", "ssh": "user@192.168.1.20", "jump": "user@192.168.1.10",
      "paths": ["/etc/server1-panel", "/etc/server1-panel.env"] }
  ]
}
```

A path missing on a given host is skipped (`tar --ignore-failed-read`), not
fatal — hosts legitimately differ.

## Restore is deliberate

`restore` extracts to a local directory (`./restore` by default) as
`DIR/<host>/<original-path>`, preserving file modes. It **never** pushes files
back onto a host — you inspect and copy back exactly what you need. Path
traversal in archive entries is contained.

## Note

A `.hlbk` archive contains your secrets (keys, tokens) — encrypted. Keep the
passphrase somewhere separate; without it the archive is unrecoverable. The
provided `.gitignore` excludes `*.hlbk` and `backup.json`.
