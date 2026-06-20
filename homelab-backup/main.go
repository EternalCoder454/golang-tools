// Command homelab-backup snapshots important configuration off one or more hosts
// over SSH into a single timestamped, AES-256-GCM-encrypted archive — and
// restores it. Built as disaster insurance for a homelab whose nodes are
// awkward to reach (e.g. a Pi you mustn't lose Wi-Fi to).
//
// The archive is gzip(tar) of every host's files under a per-host directory,
// sealed with AES-256-GCM. The key is PBKDF2-HMAC-SHA256(passphrase, salt) —
// hand-rolled on the standard library, so the tool has zero dependencies. A
// wrong passphrase fails the GCM authentication tag with a clear error.
//
//	homelab-backup backup  [-c backup.json] [-passfile F]
//	homelab-backup list    <archive> [-passfile F]
//	homelab-backup restore <archive> [-o DIR] [-passfile F]
//
// Restore extracts locally for you to inspect and copy back — it never pushes
// files onto a host automatically. Passphrase: -passfile, else $HLBK_PASSPHRASE,
// else an interactive no-echo prompt.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	magic     = "HLBK1\n"
	pbkdfIter = 600_000
)

type Source struct {
	Name    string   `json:"name"`
	SSH     string   `json:"ssh"`
	Jump    string   `json:"jump,omitempty"`
	Paths   []string `json:"paths"`
	Exclude []string `json:"exclude,omitempty"` // tar --exclude patterns (e.g. "*.db")
}

type Config struct {
	Sources []Source `json:"sources"`
	SSHKey  string   `json:"ssh_key,omitempty"`
	OutDir  string   `json:"out_dir,omitempty"`
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "homelab-backup: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "backup":
		cmdBackup(os.Args[2:])
	case "restore":
		cmdRestore(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "-init", "init":
		writeSample("backup.json")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `homelab-backup — encrypted config snapshots over SSH

  backup  [-c backup.json] [-passfile F]     snapshot all sources → encrypted archive
  list    <archive> [-passfile F]            list what's inside an archive
  restore <archive> [-o DIR] [-passfile F]   decrypt + extract locally (default ./restore)
  init                                        write a starter backup.json
`)
}

// ---- backup ----

func cmdBackup(args []string) {
	fs := newFlags("backup")
	cfgPath := fs.cfg
	passfile := fs.passfile
	keep := fs.set.Int("keep", 0, "after writing, keep only the newest N archives in out_dir (0 = all)")
	fs.parse(args)

	cfg := loadConfig(*cfgPath)
	pass, err := readPassphrase(*passfile, true)
	if err != nil {
		die("%v", err)
	}

	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)
	files := 0
	for _, s := range cfg.Sources {
		n, err := addSource(tw, cfg, s)
		if err != nil {
			die("%s: %v", s.Name, err)
		}
		files += n
		fmt.Printf("  %-12s %d file(s)\n", s.Name, n)
	}
	tw.Close()
	gz.Close()

	sealed, err := seal(plain.Bytes(), pass)
	if err != nil {
		die("encrypt: %v", err)
	}
	outDir := cfg.OutDir
	if outDir == "" {
		outDir = "."
	}
	os.MkdirAll(outDir, 0o755)
	name := filepath.Join(outDir, "homelab-backup-"+time.Now().Format("20060102-150405")+".hlbk")
	if err := os.WriteFile(name, sealed, 0o600); err != nil {
		die("write: %v", err)
	}
	fmt.Printf("✓ %s  (%d files, %s encrypted)\n", name, files, human(len(sealed)))
	if *keep > 0 {
		pruneArchives(outDir, *keep)
	}
}

// pruneArchives keeps only the newest N timestamped *.hlbk archives in dir.
// Names sort lexically = chronologically (homelab-backup-YYYYMMDD-HHMMSS.hlbk).
func pruneArchives(dir string, keep int) {
	matches, _ := filepath.Glob(filepath.Join(dir, "homelab-backup-*.hlbk"))
	if len(matches) <= keep {
		return
	}
	sort.Strings(matches)
	for _, old := range matches[:len(matches)-keep] {
		if os.Remove(old) == nil {
			fmt.Printf("  pruned %s\n", filepath.Base(old))
		}
	}
}

// addSource streams `sudo tar` from a host and re-writes its entries under
// <source name>/ into the combined archive.
func addSource(tw *tar.Writer, cfg Config, s Source) (int, error) {
	if len(s.Paths) == 0 {
		return 0, nil
	}
	// --ignore-failed-read: a path that doesn't exist on this host is skipped,
	// not fatal (hosts legitimately differ). tar then exits 0, or 1 for benign
	// warnings (a file changed while reading) — both fine; ≥2 is a real failure.
	excl := ""
	for _, e := range s.Exclude {
		excl += "--exclude=" + shq(e) + " "
	}
	remote := "sudo tar --ignore-failed-read " + excl + "-cf - " + strings.Join(quoteAll(s.Paths), " ") + " 2>/dev/null"
	args := append(sshBase(cfg, s.Jump), s.SSH, remote)
	cmd := exec.Command("ssh", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	count := 0
	tr := tar.NewReader(stdout)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("read remote tar: %w", err)
		}
		hdr.Name = s.Name + "/" + strings.TrimPrefix(hdr.Name, "./")
		if err := tw.WriteHeader(hdr); err != nil {
			return count, err
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := io.Copy(tw, tr); err != nil {
				return count, err
			}
			count++
		}
	}
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() > 1 {
			return count, fmt.Errorf("ssh tar (exit %v) — host reachable? path readable?", err)
		}
	}
	return count, nil
}

// ---- restore / list ----

func cmdRestore(args []string) {
	if len(args) == 0 {
		die("usage: restore <archive> [-o DIR] [-passfile F]")
	}
	archive := args[0]
	fs := newFlags("restore")
	out := fs.set.String("o", "restore", "output directory")
	passfile := fs.passfile
	fs.parse(args[1:])

	plain := openArchive(archive, *passfile)
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		die("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			die("tar: %v", err)
		}
		dest := filepath.Join(*out, filepath.Clean("/"+hdr.Name)) // contain path traversal
		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(dest, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(dest), 0o755)
			f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				die("write %s: %v", dest, err)
			}
			io.Copy(f, tr)
			f.Close()
			n++
		}
	}
	fmt.Printf("✓ restored %d file(s) to %s/  (inspect, then copy back what you need)\n", n, *out)
}

func cmdList(args []string) {
	if len(args) == 0 {
		die("usage: list <archive> [-passfile F]")
	}
	archive := args[0]
	fs := newFlags("list")
	passfile := fs.passfile
	fs.parse(args[1:])

	plain := openArchive(archive, *passfile)
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		die("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			die("tar: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			fmt.Printf("%9s  %s\n", human(int(hdr.Size)), hdr.Name)
		}
	}
}

func openArchive(path, passfile string) []byte {
	sealed, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	pass, err := readPassphrase(passfile, false)
	if err != nil {
		die("%v", err)
	}
	plain, err := unseal(sealed, pass)
	if err != nil {
		die("decrypt: %v (wrong passphrase or corrupt archive)", err)
	}
	return plain
}

// ---- crypto (AES-256-GCM, PBKDF2-HMAC-SHA256 key) ----

func seal(plaintext, pass []byte) ([]byte, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(pass, salt)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, []byte(magic))
	var buf bytes.Buffer
	buf.WriteString(magic)
	binary.Write(&buf, binary.BigEndian, uint32(pbkdfIter))
	buf.Write(salt)
	buf.Write(nonce)
	buf.Write(ct)
	return buf.Bytes(), nil
}

func unseal(sealed, pass []byte) ([]byte, error) {
	if len(sealed) < len(magic)+4+16+12 || string(sealed[:len(magic)]) != magic {
		return nil, errors.New("not a homelab-backup archive")
	}
	p := sealed[len(magic):]
	iter := binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	salt, nonce, ct := p[:16], p[16:28], p[28:]
	gcm, err := newGCMIter(pass, salt, int(iter))
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, []byte(magic))
}

func newGCM(pass, salt []byte) (cipher.AEAD, error)       { return newGCMIter(pass, salt, pbkdfIter) }
func newGCMIter(pass, salt []byte, iter int) (cipher.AEAD, error) {
	key := pbkdf2SHA256(pass, salt, iter, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2SHA256 — RFC 2898 PBKDF2 with HMAC-SHA256, stdlib only.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	const hLen = sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	var idx [4]byte
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf := hmac.New(sha256.New, password)
		prf.Write(salt)
		prf.Write(idx[:])
		u := prf.Sum(nil)
		t := make([]byte, hLen)
		copy(t, u)
		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// ---- helpers ----

type flags struct {
	set      *flag.FlagSet
	cfg      *string
	passfile *string
}

// newFlags gives each subcommand a flag set sharing -c / -passfile.
func newFlags(name string) flags {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return flags{
		set:      fs,
		cfg:      fs.String("c", "backup.json", "config file"),
		passfile: fs.String("passfile", "", "read passphrase from this file"),
	}
}
func (f flags) parse(args []string) { f.set.Parse(args) }

func loadConfig(path string) Config {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v (run `homelab-backup init`)", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		die("parse %s: %v", path, err)
	}
	if len(c.Sources) == 0 {
		die("config has no sources")
	}
	return c
}

func sshBase(cfg Config, jump string) []string {
	var a []string
	if cfg.SSHKey != "" {
		a = append(a, "-i", expand(cfg.SSHKey))
	}
	a = append(a, "-o", "ConnectTimeout=20")
	if jump != "" {
		a = append(a, "-o", "ProxyJump="+jump)
	}
	return a
}

func readPassphrase(passfile string, confirm bool) ([]byte, error) {
	if passfile != "" {
		b, err := os.ReadFile(passfile)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(b, "\r\n"), nil
	}
	if v := os.Getenv("HLBK_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	pw, err := readNoEcho()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm: ")
		pw2, _ := readNoEcho()
		fmt.Fprintln(os.Stderr)
		if !bytes.Equal(pw, pw2) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return pw, nil
}

func readNoEcho() ([]byte, error) {
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	off.Run()
	defer func() {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		on.Run()
	}()
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return []byte(strings.TrimRight(line, "\r\n")), err
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = shq(s)
	}
	return out
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func human(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func writeSample(path string) {
	if _, err := os.Stat(path); err == nil {
		die("%s already exists", path)
	}
	c := Config{
		SSHKey: "~/.ssh/id_ed25519",
		OutDir: ".",
		Sources: []Source{
			{Name: "server1", SSH: "user@192.168.1.10", Paths: []string{"/etc/server1-panel", "/etc/nftables.conf"}},
			{Name: "pi", SSH: "user@192.168.1.20", Jump: "user@192.168.1.10", Paths: []string{"/etc/server1-panel", "/etc/server1-panel.env", "/etc/nftables.conf"}},
		},
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		die("write: %v", err)
	}
	fmt.Printf("wrote %s — edit it, then run `homelab-backup backup`\n", path)
}
