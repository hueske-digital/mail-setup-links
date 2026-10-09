package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	checkInterval = time.Hour
	obtainTimeout = 5 * time.Minute
)

// ManagerOptions configures a Manager.
type ManagerOptions struct {
	DirectoryURL string
	Email        string
	// Hostname is the public hostname the certificate is issued for.
	Hostname string
	DataDir  string
	Now      func() time.Time
	Log      *slog.Logger
}

// Manager obtains and renews the signing certificate for the public hostname via ACME
// HTTP-01 and signs profiles with it. Challenge responses are kept in memory, so only one
// instance may run per hostname.
type Manager struct {
	opts ManagerOptions

	mu         sync.RWMutex
	material   *Material
	challenges map[string]string
}

// NewManager loads a previously stored certificate from the data directory, if any.
func NewManager(opts ManagerOptions) (*Manager, error) {
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, err
	}
	manager := &Manager{opts: opts, challenges: map[string]string{}}
	stored, err := os.ReadFile(manager.materialPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if manager.material, err = decodeMaterial(stored); err != nil {
			return nil, fmt.Errorf("reading %s: %w", manager.materialPath(), err)
		}
	}
	return manager, nil
}

// The file names carry a digest of the configuration they belong to. After a change of the
// ACME directory or the hostname the stored certificate is not found and a new one is
// obtained, instead of signing with a certificate of the wrong CA or name.

func fileDigest(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(digest[:6])
}

func (m *Manager) materialPath() string {
	return filepath.Join(m.opts.DataDir, "signing-"+fileDigest(m.opts.DirectoryURL, m.opts.Hostname)+".pem")
}

func (m *Manager) accountKeyPath() string {
	return filepath.Join(m.opts.DataDir, "acme-account-"+fileDigest(m.opts.DirectoryURL)+".pem")
}

// Sign signs content with the current certificate. It returns ErrUnavailable if there is
// none or it is outside its validity period.
func (m *Manager) Sign(content []byte) ([]byte, error) {
	m.mu.RLock()
	material := m.material
	m.mu.RUnlock()

	now := m.opts.Now()
	if material == nil || now.Before(material.Chain[0].NotBefore) || !now.Before(material.Chain[0].NotAfter) {
		return nil, ErrUnavailable
	}
	return Sign(content, material)
}

// Challenge returns the HTTP-01 key authorization for a pending challenge token.
func (m *Manager) Challenge(token string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	response, ok := m.challenges[token]
	return response, ok
}

// Run keeps the certificate renewed until ctx is cancelled. Start it once the HTTP server
// answers challenge requests. Failures are logged and retried on the next check.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		m.ensure(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) ensure(ctx context.Context) {
	m.mu.RLock()
	current := m.material
	m.mu.RUnlock()
	if current != nil && !renewalDue(current.Chain[0], m.opts.Now()) {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, obtainTimeout)
	defer cancel()
	material, err := m.obtain(ctx)
	if err != nil {
		m.opts.Log.Error("obtaining signing certificate failed", "error", err)
		return
	}
	// The certificate only becomes current after it has been stored.
	if err := m.store(material); err != nil {
		m.opts.Log.Error("storing signing certificate failed", "error", err)
		return
	}
	m.mu.Lock()
	m.material = material
	m.mu.Unlock()
	m.opts.Log.Info("signing certificate obtained", "notAfter", material.Chain[0].NotAfter.UTC())
}

func (m *Manager) obtain(ctx context.Context) (*Material, error) {
	accountKey, err := m.accountKey()
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: m.opts.DirectoryURL}
	account := &acme.Account{Contact: []string{"mailto:" + m.opts.Email}}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register account: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.opts.Hostname))
	if err != nil {
		return nil, fmt.Errorf("create order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := m.authorize(ctx, client, authzURL); err != nil {
			return nil, err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("wait for order: %w", err)
	}

	// RSA, because it is the key type every iOS and macOS version accepts for profile signatures.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{m.opts.Hostname}}, key)
	if err != nil {
		return nil, err
	}
	chainDER, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize order: %w", err)
	}
	material := &Material{Key: key}
	for _, der := range chainDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		material.Chain = append(material.Chain, certificate)
	}
	return material, nil
}

func (m *Manager) authorize(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("get authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	var challenge *acme.Challenge
	for _, candidate := range authz.Challenges {
		if candidate.Type == "http-01" {
			challenge = candidate
		}
	}
	if challenge == nil {
		return errors.New("ACME server offers no http-01 challenge")
	}
	response, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.challenges[challenge.Token] = response
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.challenges, challenge.Token)
		m.mu.Unlock()
	}()

	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("wait for authorization: %w", err)
	}
	return nil
}

func (m *Manager) accountKey() (crypto.Signer, error) {
	stored, err := os.ReadFile(m.accountKeyPath())
	if err == nil {
		block, _ := pem.Decode(stored)
		if block == nil {
			return nil, errors.New("stored account key is not PEM")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeAtomic(m.accountKeyPath(), encoded); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *Manager) store(material *Material) error {
	encoded, err := encodeMaterial(material)
	if err != nil {
		return err
	}
	return writeAtomic(m.materialPath(), encoded)
}

func writeAtomic(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
