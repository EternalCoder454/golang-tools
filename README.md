# golang-tools

A collection of small, **dependency-free** (where possible) Go command-line
tools for running a homelab. Each lives in its own directory and is its own
module, so you can build or `go install` any of them independently.

| Tool | What it does |
|------|--------------|
| [**homelab-ca**](homelab-ca/) | Tiny certificate authority — create a CA and issue/renew/add-SAN leaf certs. Pure stdlib. |
| [**secscan**](secscan/) | Pre-push secret scanner — flags private keys, tokens, and secret-looking assignments before you push. Pure stdlib. |
| [**goship**](goship/) | One-command deploy — cross-compile → scp (ProxyJump) → install → restart → health-check → auto-rollback. Pure stdlib. |
| [**homelab-backup**](homelab-backup/) | Encrypted (AES-256-GCM) config snapshots over SSH, with restore. Pure stdlib. |
| [**ttf2woff2**](ttf2woff2/) | Convert TTF/OTF fonts to WOFF2. One dep: `andybalholm/brotli` (WOFF2 mandates Brotli). |

## Build / install

```sh
# build one tool
cd secscan && go build -o secscan .

# or install straight from GitHub
go install github.com/EternalCoder454/golang-tools/secscan@latest
```

Each tool's directory has its own README with usage and examples.

## License

MIT
