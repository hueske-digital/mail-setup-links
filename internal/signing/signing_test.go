package signing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// The CMS signing time is the real clock, so the test certificate is valid around now.
var issued = time.Now().AddDate(0, 0, -1).Truncate(time.Second)

// newMaterial returns a leaf valid for 90 days from `issued`, its CA and a pool trusting that CA.
func newMaterial(t *testing.T) (*Material, *x509.CertPool) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             issued,
		NotAfter:              issued.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"setup.example.net"},
		NotBefore:    issued,
		NotAfter:     issued.AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &Material{Key: leafKey, Chain: []*x509.Certificate{leaf}}, pool
}

func TestSignProducesVerifiableCMS(t *testing.T) {
	material, pool := newMaterial(t)
	content := []byte("<plist>profile</plist>")

	signed, err := Sign(content, material)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Content, content) {
		t.Error("signed data does not embed the profile")
	}
	if err := parsed.VerifyWithChainAtTime(pool, time.Now()); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}

	parsed.Content = []byte("<plist>tampered</plist>")
	if err := parsed.VerifyWithChainAtTime(pool, time.Now()); err == nil {
		t.Error("tampered content must not verify")
	}
}

func TestRenewalDue(t *testing.T) {
	material, _ := newMaterial(t)
	leaf := material.Chain[0]
	if renewalDue(leaf, issued.AddDate(0, 0, 59)) {
		t.Error("renewal must not be due before two thirds of the lifetime")
	}
	if !renewalDue(leaf, issued.AddDate(0, 0, 60)) {
		t.Error("renewal must be due after two thirds of the lifetime")
	}
}

func TestManagerLoadsStoredMaterialAndChecksValidity(t *testing.T) {
	material, pool := newMaterial(t)
	dir := t.TempDir()
	now := issued.AddDate(0, 0, 1)
	opts := ManagerOptions{
		DirectoryURL: "https://ca.example.net/dir", Hostname: "setup.example.net",
		DataDir: dir, Now: func() time.Time { return now }, Log: slog.New(slog.DiscardHandler),
	}
	issuer, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.store(material); err != nil {
		t.Fatal(err)
	}

	manager, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := manager.Sign([]byte("profile"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyWithChainAtTime(pool, now); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}

	now = issued.AddDate(0, 0, 91)
	if _, err := manager.Sign([]byte("profile")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("expired certificate: got %v, want ErrUnavailable", err)
	}
}

func TestManagerIgnoresCertificatesOfAnotherConfiguration(t *testing.T) {
	material, _ := newMaterial(t)
	opts := ManagerOptions{
		DirectoryURL: "https://staging.example.net/dir", Hostname: "setup.example.net",
		DataDir: t.TempDir(), Now: time.Now, Log: slog.New(slog.DiscardHandler),
	}
	issuer, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.store(material); err != nil {
		t.Fatal(err)
	}

	changes := map[string]func(*ManagerOptions){
		"other directory": func(o *ManagerOptions) { o.DirectoryURL = "https://production.example.net/dir" },
		"other hostname":  func(o *ManagerOptions) { o.Hostname = "other.example.net" },
	}
	for name, change := range changes {
		changed := opts
		change(&changed)
		manager, err := NewManager(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Sign([]byte("profile")); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: got %v, want ErrUnavailable", name, err)
		}
	}
}

func TestManagerWithoutCertificateIsUnavailable(t *testing.T) {
	manager, err := NewManager(ManagerOptions{DataDir: t.TempDir(), Now: time.Now, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Sign([]byte("profile")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("got %v, want ErrUnavailable", err)
	}
	if _, ok := manager.Challenge("unknown"); ok {
		t.Error("unknown challenge token must not resolve")
	}
}
