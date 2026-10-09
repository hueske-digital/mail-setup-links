// Package token seals link data into opaque, authenticated URL tokens.
package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const (
	version = 1
	// KeySize is the required key length in bytes (AES-256).
	KeySize = 32
	// maxLength bounds the work done for a token taken from a URL.
	maxLength = 2048
)

// ErrTooLong is returned by Seal for payloads whose token would exceed the length limit.
var ErrTooLong = errors.New("payload too long for a token")

// ErrInvalid is returned for tokens that are malformed or were not sealed with this key.
var ErrInvalid = errors.New("invalid token")

// Codec encodes values as base64url(version | nonce | AES-256-GCM ciphertext).
type Codec struct {
	aead cipher.AEAD
}

func New(key []byte) (*Codec, error) {
	if len(key) != KeySize {
		return nil, errors.New("token key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead}, nil
}

// Seal encrypts payload. It fails with ErrTooLong instead of returning a token that Open
// would reject.
func (c *Codec) Seal(payload any) (string, error) {
	// Without HTML escaping "&", "<" and ">" take one byte instead of six.
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return "", err
	}
	plaintext := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	header := []byte{version}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(append(header, nonce...), nonce, plaintext, header)
	token := base64.RawURLEncoding.EncodeToString(sealed)
	if len(token) > maxLength {
		return "", ErrTooLong
	}
	return token, nil
}

// Open decrypts token into payload. Every failure is reported as ErrInvalid.
func (c *Codec) Open(token string, payload any) error {
	if len(token) > maxLength {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) < 1+c.aead.NonceSize()+c.aead.Overhead() || raw[0] != version {
		return ErrInvalid
	}
	header, nonce, ciphertext := raw[:1], raw[1:1+c.aead.NonceSize()], raw[1+c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return ErrInvalid
	}
	if err := json.Unmarshal(plaintext, payload); err != nil {
		return ErrInvalid
	}
	return nil
}
