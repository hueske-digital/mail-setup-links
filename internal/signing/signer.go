// Package signing wraps configuration profiles in a CMS signature and keeps the
// signing certificate renewed via ACME.
package signing

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/smallstep/pkcs7"
)

// ErrUnavailable is returned when no currently valid signing certificate exists.
var ErrUnavailable = errors.New("no valid signing certificate")

// Material is a private key with its certificate chain, leaf first.
type Material struct {
	Key   crypto.Signer
	Chain []*x509.Certificate
}

// Sign returns a DER encoded CMS SignedData structure with content embedded (not detached).
func Sign(content []byte, material *Material) ([]byte, error) {
	signedData, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signedData.AddSignerChain(material.Chain[0], material.Key, material.Chain[1:], pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return signedData.Finish()
}

// renewalDue reports whether two thirds of the certificate lifetime have passed.
func renewalDue(leaf *x509.Certificate, now time.Time) bool {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return !now.Before(leaf.NotBefore.Add(lifetime * 2 / 3))
}

func encodeMaterial(material *Material) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(material.Key)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, err
	}
	for _, certificate := range material.Chain {
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func decodeMaterial(data []byte) (*Material, error) {
	material := &Material{}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, errors.New("stored key cannot sign")
			}
			material.Key = signer
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			material.Chain = append(material.Chain, certificate)
		}
	}
	if material.Key == nil || len(material.Chain) == 0 {
		return nil, errors.New("stored signing material is incomplete")
	}
	return material, nil
}
