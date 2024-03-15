package virtualwebauthn

type Key struct {
	Type KeyType `json:"type"`
	Data []byte  `json:"data"`
	signingKey
}

func (k *Key) AttestationData(wrongAlg bool) []byte {
	k.ensureSigningKey(wrongAlg)
	return k.signingKey.AttestationData()
}

func (k *Key) Sign(digest []byte) (signature []byte, err error) {
	k.ensureSigningKey(false)
	return k.signingKey.Sign(digest)
}

func (k *Key) GetKeypair() interface{} {
	k.ensureSigningKey(false)
	return k.signingKey
}

func (k *Key) ensureSigningKey(wrongAlg bool) {
	switch k.Type {
	case KeyTypeEC2:
		k.signingKey = importEC2SigningKey(k.Data, wrongAlg)
	case KeyTypeRSA:
		k.signingKey = importRSASigningKey(k.Data, wrongAlg)
	default:
		panic("invalid key type")
	}
}

type KeyType string

const (
	KeyTypeEC2 KeyType = "ec2"
	KeyTypeRSA KeyType = "rsa"
)

func (keyType KeyType) newKey() *Key {
	key := &Key{Type: keyType}
	switch keyType {
	case KeyTypeEC2:
		key.signingKey, key.Data = newEC2SigningKey()
	case KeyTypeRSA:
		key.signingKey, key.Data = newRSASigningKey()
	default:
		panic("invalid key type")
	}
	return key
}

func (keyType KeyType) importKey(keyData []byte) *Key {
	return &Key{Type: keyType, Data: keyData}
}

type signingKey interface {
	// AttestationData contains public key information and more
	AttestationData() []byte
	Sign(digest []byte) (signature []byte, err error)
}
