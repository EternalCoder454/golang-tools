package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "CA directory")
	name := fs.String("name", "Homelab CA", "CA common name")
	years := fs.Int("years", 10, "CA validity in years")
	force := fs.Bool("force", false, "overwrite an existing CA")
	fs.Parse(args)

	crtP, keyP := caPaths(*dir)
	if _, err := os.Stat(crtP); err == nil && !*force {
		return fmt.Errorf("CA already exists at %s (use -force to overwrite)", crtP)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: *name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(*years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // issues leaves only, no sub-CAs
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeCert(crtP, der); err != nil {
		return err
	}
	if err := writeKey(keyP, key); err != nil {
		return err
	}
	fmt.Printf("✓ created CA %q\n  %s\n  %s (keep this private — never copy it to a node)\n  valid %d years\n",
		*name, crtP, keyP, *years)
	return nil
}

func cmdIssue(args []string) error {
	sans, rest := sanArgs(args)
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "CA directory")
	cn := fs.String("cn", "", "leaf common name (required)")
	certOut := fs.String("cert", "", "output cert path (default <cn>.crt)")
	keyOut := fs.String("key", "", "output key path (default <cn>.key)")
	days := fs.Int("days", 825, "validity in days (≤825 keeps browsers happy)")
	fs.Parse(rest)
	if *cn == "" {
		return fmt.Errorf("-cn is required")
	}
	if *certOut == "" {
		*certOut = *cn + ".crt"
	}
	if *keyOut == "" {
		*keyOut = *cn + ".key"
	}
	caCrt, caKey, err := loadCA(*dir)
	if err != nil {
		return err
	}
	dns, ips, err := parseSANs(sans)
	if err != nil {
		return err
	}
	if len(dns) == 0 && len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "warning: no -san given; modern clients ignore the CN, so this cert won't validate for any hostname")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := leafTemplate(*cn, dns, ips, *days)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCrt, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := verifyChain(der, caCrt); err != nil {
		return fmt.Errorf("self-check failed: %w", err)
	}
	if err := writeCert(*certOut, der); err != nil {
		return err
	}
	if err := writeKey(*keyOut, leafKey); err != nil {
		return err
	}
	fmt.Printf("✓ issued %q  (valid %d days)\n  cert: %s\n  key:  %s\n  SANs: %s\n",
		*cn, *days, *certOut, *keyOut, sanSummary(dns, ips))
	return nil
}

// cmdReissue handles add-san (merge new SANs into an existing leaf) and renew
// (same SANs, fresh validity). The leaf key is reused, so an already-deployed
// key.pem stays valid — only the cert file is rewritten.
func cmdReissue(args []string, renew bool) error {
	sans, rest := sanArgs(args)
	name := "add-san"
	if renew {
		name = "renew"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "CA directory")
	certPath := fs.String("cert", "", "leaf cert to re-sign (required)")
	keyPath := fs.String("key", "", "leaf key to reuse (required)")
	days := fs.Int("days", 825, "new validity in days")
	fs.Parse(rest)
	if *certPath == "" || *keyPath == "" {
		return fmt.Errorf("-cert and -key are required")
	}
	caCrt, caKey, err := loadCA(*dir)
	if err != nil {
		return err
	}
	old, err := loadCert(*certPath)
	if err != nil {
		return err
	}
	leafKey, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	dns := append([]string{}, old.DNSNames...)
	ips := append([]net.IP{}, old.IPAddresses...)
	if !renew {
		nd, ni, err := parseSANs(sans)
		if err != nil {
			return err
		}
		if len(nd) == 0 && len(ni) == 0 {
			return fmt.Errorf("add-san needs at least one -san")
		}
		dns = dedupDNS(append(dns, nd...))
		ips = dedupIP(append(ips, ni...))
	}
	tmpl := leafTemplate(old.Subject.CommonName, dns, ips, *days)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCrt, leafKey.Public(), caKey)
	if err != nil {
		return err
	}
	if err := verifyChain(der, caCrt); err != nil {
		return fmt.Errorf("self-check failed: %w", err)
	}
	if err := writeCert(*certPath, der); err != nil {
		return err
	}
	verb := "renewed"
	if !renew {
		verb = "re-signed with added SANs"
	}
	fmt.Printf("✓ %s %q  (valid %d days; key unchanged)\n  cert: %s\n  SANs: %s\n",
		verb, old.Subject.CommonName, *days, *certPath, sanSummary(dns, ips))
	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	certPath := fs.String("cert", "", "certificate to inspect (required)")
	fs.Parse(args)
	if *certPath == "" {
		return fmt.Errorf("-cert is required")
	}
	c, err := loadCert(*certPath)
	if err != nil {
		return err
	}
	left := time.Until(c.NotAfter)
	fmt.Printf("Subject CN : %s\n", c.Subject.CommonName)
	fmt.Printf("Issuer CN  : %s\n", c.Issuer.CommonName)
	fmt.Printf("Serial     : %x\n", c.SerialNumber)
	fmt.Printf("Type       : %s\n", map[bool]string{true: "CA", false: "leaf (server)"}[c.IsCA])
	fmt.Printf("Valid      : %s → %s  (%d days left)\n",
		c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), int(left.Hours()/24))
	if left < 0 {
		fmt.Println("           : ⚠ EXPIRED")
	}
	if !c.IsCA {
		fmt.Printf("SANs       : %s\n", sanSummary(c.DNSNames, c.IPAddresses))
	}
	return nil
}

func leafTemplate(cn string, dns []string, ips []net.IP, days int) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
}

func verifyChain(leafDER []byte, ca *x509.Certificate) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func dedupDNS(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		k := normalizeDNS(d)
		if !seen[k] {
			seen[k] = true
			out = append(out, d)
		}
	}
	return out
}

func dedupIP(in []net.IP) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	for _, ip := range in {
		k := ip.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, ip)
		}
	}
	return out
}

func normalizeDNS(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
