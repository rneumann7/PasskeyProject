package virtualwebauthn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type TestFlags struct {
	WrongType            bool
	WrongCOSEAlg         bool
	WrongAlg             bool
	WrongSig             bool
	RequireRK            bool
	NoneAttestation      bool
	WrongNoneAttestation bool
	CertAttestation      bool
	WrongCertAttestation bool
}

type PublicKeyCredentialSource struct {
	Type       string     `json:"type"`
	Credential Credential `json:"credential"`
	RpID       string     `json:"rpId"`
}

type ClientDataInterface interface {
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// encrypts a publickey-credential-source with AES-GCM
func encryptCredential(cred PublicKeyCredentialSource, key []byte) ([]byte, error) {
	// serialize the credential
	credBytes, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	// create a new AES cipher block with the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// wrap the AES block cipher in Galois Counter Mode (GCM)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Generate a nonce, used as the initialization vector
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// encrypt the serialized cred using the GCM block mode and the nonce
	ciphertext := gcm.Seal(nonce, nonce, credBytes, nil)
	return ciphertext, nil
}

// decrypts a publickey-credential-source with AES-GCM
func decryptCredential(ciphertext []byte, key []byte) (PublicKeyCredentialSource, error) {
	// create a new AES cipher block with the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return PublicKeyCredentialSource{}, err
	}
	// wrap the AES block cipher in Galois Counter Mode (GCM)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return PublicKeyCredentialSource{}, err
	}
	// get the nonce size
	nonceSize := gcm.NonceSize()
	// separate the nonce from the ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// decrypt the ciphertext using the GCM block mode and the nonce
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return PublicKeyCredentialSource{}, err
	}
	// deserialize the cred
	var cred PublicKeyCredentialSource
	err = json.Unmarshal(plaintext, &cred)
	if err != nil {
		return PublicKeyCredentialSource{}, err
	}
	return cred, nil
}

// creates a new self-signed x509 certificate
func createCertificate(keypair *Key) []byte {

	// get the specific key from the keypair
	var rsaKey *rsaSigningKey
	var ec2Key *ec2SigningKey
	switch keypair.Type {
	case KeyTypeEC2:
		ec2Key = keypair.GetKeypair().(*ec2SigningKey)
	case KeyTypeRSA:
		rsaKey = keypair.GetKeypair().(*rsaSigningKey)
	default:
		panic("invalid key type")
	}

	// Create a new random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Version:      3,
		Subject: pkix.Name{
			Country:            []string{"DE"},
			Organization:       []string{"SuperSafeAuthenticators"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "SuperSafeAuthenticator",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for one year
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	// Create a self-signed certificate
	certBytes := []byte{}
	if ec2Key != nil {
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &ec2Key.privateKey.PublicKey, ec2Key.privateKey)
		// Save the certificate to a file
		certFile, err := os.Create("cert.pem")
		if err != nil {
			panic(err)
		}
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		certFile.Close()
	}
	if rsaKey != nil {
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &rsaKey.privateKey.PublicKey, rsaKey.privateKey)
	}
	if err != nil {
		panic(err)
	}
	return certBytes
}

func marshalCbor(v any) []byte {
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic("failed to instantiate cbor encoder")
	}
	bytes, err := encoder.Marshal(v)
	if err != nil {
		panic("failed to encode to cbor")
	}
	return bytes
}

func randomBytes(length int) []byte {
	bytes := make([]byte, length)
	num, err := rand.Read(bytes)
	if err != nil || num != length {
		panic("failed to generate random bytes")
	}
	return bytes
}

func bigEndianBytes[T interface{ int | uint32 }](value T, length int) []byte {
	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		shift := (length - i - 1) * 8
		bytes[i] = byte(value >> shift & 0xFF)
	}
	return bytes
}

func authenticatorDataFlags(userPresent, userVerified, attestation, extensions bool) byte {
	// https://www.w3.org/TR/webauthn/#flags
	flags := byte(0)
	if userPresent {
		flags |= 1 << 0
	}
	if userVerified {
		flags |= 1 << 2
	}
	if attestation {
		flags |= 1 << 6
	}
	if extensions { // extensions not supported yet
		flags |= 1 << 7
	}
	return flags
}
