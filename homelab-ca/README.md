# homelab-ca

A tiny certificate authority manager for a homelab — **pure standard library, no
dependencies**. Creates a local CA and issues/renews leaf (server) certificates
with arbitrary DNS + IP SANs, so you stop hand-writing openssl SAN configs and
re-signing certs just to add a name.

Keys are ECDSA P-256; leaves get the `serverAuth` EKU and an 825-day validity
(the max modern browsers accept). Output is a PEM cert + PKCS#8 key, ready to
drop in as e.g. `/etc/server1-panel/cert.pem` + `key.pem`.

## Build

```sh
go build -o homelab-ca .
```

## Commands

```sh
homelab-ca init    [-dir DIR] [-name NAME] [-years N]        # create ca.crt + ca.key
homelab-ca issue   [-dir DIR] -cn CN [-san V]... [-cert F] [-key F] [-days N]
homelab-ca add-san [-dir DIR] -cert F -key F -san V... [-days N]   # add SANs, reuse key
homelab-ca renew   [-dir DIR] -cert F -key F [-days N]            # fresh validity, same SANs
homelab-ca show    -cert F                                        # inspect a cert
```

- `DIR` defaults to `~/homelab-ca` (matches the existing `ca.crt`/`ca.key` layout).
- `-san` is `dns:NAME`, `ip:ADDR`, or a bare value (auto-detected). Repeatable,
  and accepts comma-separated lists.
- The **CA key never leaves the CA dir** — only the leaf `cert.pem`/`key.pem` go
  to a node. `add-san`/`renew` reuse the leaf key, so an already-deployed
  `key.pem` stays valid; only the cert is rewritten.

## Example

```sh
# one-time
homelab-ca init -name "Homelab CA"

# issue a cert for a new box
homelab-ca issue -cn server2 \
  -san dns:server2.local -san ip:192.168.1.50 -san ip:100.64.0.9 \
  -cert /tmp/cert.pem -key /tmp/key.pem

# later: a device moves onto Tailscale — add its tailnet IP, keep the key
homelab-ca add-san -cert /tmp/cert.pem -key /tmp/key.pem -san ip:100.64.0.9
```

Every issued cert is self-checked against the CA before being written, and the
output verifies with `openssl verify -CAfile ca.crt cert.pem`.

## Note

Install `ca.crt` once into each device's trust store (browser Authorities / OS
store) and every cert this CA issues is trusted — no per-cert warnings.
