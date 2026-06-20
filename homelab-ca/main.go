// Command homelab-ca is a tiny certificate authority manager for a homelab.
//
// It creates a local CA and issues/renews leaf (server) certificates signed by
// it, with arbitrary DNS + IP SANs — replacing the openssl ritual of building a
// CA, writing a SAN config, and re-signing by hand just to add a name. Output
// is a PEM cert + PKCS#8 key ready to drop in (e.g. /etc/server1-panel/
// cert.pem + key.pem). Keys are ECDSA P-256; leaves get the serverAuth EKU.
//
// Pure standard library — no dependencies.
//
//	homelab-ca init    [-dir DIR] [-name NAME] [-years N]
//	homelab-ca issue   [-dir DIR] -cn CN [-san V]... [-cert F] [-key F] [-days N]
//	homelab-ca add-san [-dir DIR] -cert F -key F -san V... [-days N]
//	homelab-ca renew   [-dir DIR] -cert F -key F [-days N]
//	homelab-ca show    -cert F
//
// A -san value is dns:NAME, ip:ADDR, or a bare value (auto-detected); the flag
// may be repeated and also accepts comma-separated lists.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "add-san":
		err = cmdReissue(os.Args[2:], false)
	case "renew":
		err = cmdReissue(os.Args[2:], true)
	case "show":
		err = cmdShow(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `homelab-ca — tiny homelab certificate authority

  init    [-dir DIR] [-name NAME] [-years N]      create the CA (ca.crt + ca.key)
  issue   [-dir DIR] -cn CN [-san V]... ...        issue a leaf cert signed by the CA
  add-san [-dir DIR] -cert F -key F -san V... ...   add SAN(s) to a leaf and re-sign
  renew   [-dir DIR] -cert F -key F [-days N]       re-sign a leaf with fresh validity
  show    -cert F                                   print a certificate's details

DIR defaults to ~/homelab-ca.  -san is dns:NAME | ip:ADDR | bare (auto), repeatable
and comma-separated.  Example:
  homelab-ca issue -cn server2 -san dns:server2.local -san ip:192.168.1.50 -san ip:100.64.0.9
`)
}

// ---- shared helpers ----

func defaultDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "homelab-ca")
}

func caPaths(dir string) (crt, key string) {
	return filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
}

func newSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func writeCert(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if ek, ok := k.(*ecdsa.PrivateKey); ok {
			return ek, nil
		}
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return x509.ParseECPrivateKey(blk.Bytes) // SEC1 fallback (older openssl keys)
}

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	crtP, keyP := caPaths(dir)
	crt, err := loadCert(crtP)
	if err != nil {
		return nil, nil, fmt.Errorf("load CA cert (%s): %w — run `homelab-ca init` first?", crtP, err)
	}
	key, err := loadKey(keyP)
	if err != nil {
		return nil, nil, fmt.Errorf("load CA key (%s): %w", keyP, err)
	}
	return crt, key, nil
}

// parseSANs splits dns:/ip:/bare values (comma-separated allowed) into DNS names
// and IP addresses.
func parseSANs(vals []string) (dns []string, ips []net.IP, err error) {
	for _, raw := range vals {
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			lower := strings.ToLower(v)
			switch {
			case strings.HasPrefix(lower, "dns:"):
				dns = append(dns, v[4:])
			case strings.HasPrefix(lower, "ip:"):
				ip := net.ParseIP(v[3:])
				if ip == nil {
					return nil, nil, fmt.Errorf("invalid IP SAN %q", v[3:])
				}
				ips = append(ips, ip)
			default:
				if ip := net.ParseIP(v); ip != nil {
					ips = append(ips, ip)
				} else {
					dns = append(dns, v)
				}
			}
		}
	}
	return dns, ips, nil
}

// sanArgs collects repeated -san flags before the stdlib flag package, which
// doesn't support repeats. Returns the -san values and the remaining args.
func sanArgs(args []string) (sans []string, rest []string) {
	for i := 0; i < len(args); i++ {
		if args[i] == "-san" || args[i] == "--san" {
			if i+1 < len(args) {
				sans = append(sans, args[i+1])
				i++
			}
			continue
		}
		rest = append(rest, args[i])
	}
	return sans, rest
}

func sanSummary(dns []string, ips []net.IP) string {
	parts := append([]string{}, dns...)
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}
