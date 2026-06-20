# goship

Build a Go program and deploy it to one or more hosts over SSH, in one command:

**cross-compile per target arch → `scp` (optional ProxyJump) → back up the
current binary → install over it → restart its systemd unit → health-check →
auto-rollback if the health check fails.**

Pure standard library — it shells out to the `go`, `scp`, and `ssh` you already
use. Builds are cached per arch, so two same-arch targets compile once.

## Build

```sh
go build -o goship .
```

## Usage

```sh
goship [-c goship.json] [-only name,name] [-no-build]
goship -init                 # write a starter goship.json
```

Run it from your project directory (where `goship.json` lives). Remote steps use
`sudo`, so the SSH user needs **passwordless sudo** on each host.

## Config (`goship.json`)

```json
{
  "build": { "dir": ".", "env": ["CGO_ENABLED=0"] },
  "binary": "server1-panel",
  "ssh_key": "~/.ssh/id_ed25519",
  "targets": [
    { "name": "server1", "arch": "amd64",
      "ssh": "user@192.168.1.10",
      "dest": "/usr/local/bin/server1-panel", "restart": "server1-panel" },
    { "name": "pi", "arch": "arm64",
      "ssh": "user@192.168.1.20", "jump": "user@192.168.1.10",
      "dest": "/usr/local/bin/server1-panel", "restart": "server1-panel" }
  ]
}
```

| field | meaning |
|---|---|
| `build.dir` | package to build (default `.`) |
| `build.ldflags` / `build.env` | optional `-ldflags`, extra build env |
| `target.arch` | `amd64`, `arm64`, … (GOOS is always `linux`) |
| `target.jump` | optional SSH ProxyJump (`user@bastion`) |
| `target.dest` | remote install path |
| `target.restart` | systemd unit to restart (optional) |
| `target.health` | health command; defaults to `systemctl is-active <restart>` |

## Safety

Before installing, goship copies the live binary to `<dest>.goship.bak`. If the
post-restart health check fails, it reinstalls the backup and restarts — so a
bad build never leaves a host down. `goship` exits non-zero if any target fails.
