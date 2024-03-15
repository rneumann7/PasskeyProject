package virtualwebauthn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

type AuthenticatorOptions struct {
	UserHandle   []byte
	UserPresent  bool
	UserVerified bool
}

type Authenticator struct {
	Options     AuthenticatorOptions `json:"options"`
	Aaguid      [16]byte             `json:"aaguid"`
	Credentials []Credential         `json:"credentials,omitempty"`
	// Used for server-side credentials
	MasterKey []byte `json:"masterKey,omitempty"`
	// Used for attestation
	AttestationCert []byte
	AttestationKey  *rsa.PrivateKey
	// algorithm used for attestation signature
	Alg int
}

func NewAuthenticator() Authenticator {
	return NewAuthenticatorWithOptions(AuthenticatorOptions{
		UserPresent:  true,
		UserVerified: true,
	})
}

func NewAuthenticatorWithOptions(options AuthenticatorOptions) Authenticator {
	// Create 128-bit MasterKey for AES
	key := make([]byte, 16)
	rand.Read(key)
	auth := Authenticator{Options: options,
		MasterKey: key,
		Alg:       rsaSHA256Algo}
	copy(auth.Aaguid[:], randomBytes(len(auth.Aaguid)))
	return auth
}

func (a *Authenticator) AddCredential(cred Credential) {
	a.Credentials = append(a.Credentials, cred)
}

func (a *Authenticator) FindAllowedCredential(options AssertionOptions) *Credential {
	for i := range a.Credentials {
		if a.Credentials[i].IsAllowedForAssertion(options) {
			return &a.Credentials[i]
		}
	}
	return nil
}

// sign the data with the attestation key
func (a *Authenticator) Sign(digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, a.AttestationKey, crypto.SHA256, digest)
}

// read the certificate from a file
func (a *Authenticator) ReadCertificateFromFile(path string) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read the PEM file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode PEM block containing public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	a.AttestationCert = cert.Raw
}

// read the key from a file
func (a *Authenticator) ReadKeyFromFile(path string) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read the PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatalf("Failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	a.AttestationKey = privateKey
}
