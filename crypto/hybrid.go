package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	hybridKDFSalt   = "ejson/v3/x25519-mlkem768/hkdf-sha256"
	hybridAADDomain = "ejson/v3/x25519-mlkem768/xchacha20poly1305"
)

// HybridEncrypter encrypts individual JSON string values using the v3 hybrid
// X25519 + ML-KEM-768 KEM construction and XChaCha20-Poly1305.
type HybridEncrypter struct {
	PeerPublic            HybridPublicKey
	recipientX25519Public *ecdh.PublicKey
	mlkemPublic           *mlkem.EncapsulationKey768
}

// HybridDecrypter decrypts v3 hybrid boxed messages.
type HybridDecrypter struct {
	PrivateKey    HybridPrivateKey
	x25519Private *ecdh.PrivateKey
	mlkemPrivate  *mlkem.DecapsulationKey768
}

type hybridBoxedMessage struct {
	SchemaVersion         int
	EphemeralX25519Public [hybridX25519KeySize]byte
	MLKEMCiphertext       [hybridMLKEMCiphertextSize]byte
	Nonce                 [chacha20poly1305.NonceSizeX]byte
	Box                   []byte
}

// NewHybridEncrypter validates and returns a v3 hybrid encrypter.
func NewHybridEncrypter(peerPublic HybridPublicKey) (*HybridEncrypter, error) {
	recipientX25519Public, err := ecdh.X25519().NewPublicKey(peerPublic.X25519Public[:])
	if err != nil {
		return nil, fmt.Errorf("public key invalid")
	}
	mlkemPublic, err := mlkem.NewEncapsulationKey768(peerPublic.MLKEMEncapsulationKey[:])
	if err != nil {
		return nil, fmt.Errorf("public key invalid")
	}
	return &HybridEncrypter{PeerPublic: peerPublic, recipientX25519Public: recipientX25519Public, mlkemPublic: mlkemPublic}, nil
}

// NewHybridDecrypter validates and returns a v3 hybrid decrypter.
func NewHybridDecrypter(privateKey HybridPrivateKey) (*HybridDecrypter, error) {
	x25519Private, err := ecdh.X25519().NewPrivateKey(privateKey.X25519Private[:])
	if err != nil {
		return nil, fmt.Errorf("invalid private key")
	}
	mlkemPrivate, err := mlkem.NewDecapsulationKey768(privateKey.MLKEMSeed[:])
	if err != nil {
		return nil, fmt.Errorf("invalid private key")
	}
	return &HybridDecrypter{PrivateKey: privateKey, x25519Private: x25519Private, mlkemPrivate: mlkemPrivate}, nil
}

// Encrypt takes a plaintext message and returns a v3 hybrid boxed message. If
// the input already looks like any supported ejson boxed message, it is returned
// unchanged to preserve ejson's no-reencrypt behavior.
func (e *HybridEncrypter) Encrypt(message []byte) ([]byte, error) {
	if IsBoxedMessage(message) {
		return message, nil
	}
	boxed, err := e.encrypt(message)
	if err != nil {
		return nil, err
	}
	return boxed.Dump(), nil
}

func (e *HybridEncrypter) encrypt(message []byte) (*hybridBoxedMessage, error) {
	ephemeralX25519Private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	x25519SharedSecret, err := ephemeralX25519Private.ECDH(e.recipientX25519Public)
	if err != nil {
		return nil, err
	}

	mlkemSharedSecret, mlkemCiphertext := e.mlkemPublic.Encapsulate()

	ephemeralX25519Public := ephemeralX25519Private.PublicKey().Bytes()
	key, aad, err := deriveHybridAEADKeyAndAAD(e.PeerPublic, ephemeralX25519Public, mlkemCiphertext, x25519SharedSecret, mlkemSharedSecret)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	box := aead.Seal(nil, nonce[:], message, aad)

	var out hybridBoxedMessage
	out.SchemaVersion = SchemaVersionHybrid
	copy(out.EphemeralX25519Public[:], ephemeralX25519Public)
	copy(out.MLKEMCiphertext[:], mlkemCiphertext)
	copy(out.Nonce[:], nonce[:])
	out.Box = box
	return &out, nil
}

// Decrypt takes a v3 hybrid boxed message and returns the decrypted plaintext.
func (d *HybridDecrypter) Decrypt(message []byte) ([]byte, error) {
	var bm hybridBoxedMessage
	if err := bm.Load(message); err != nil {
		return nil, err
	}
	return d.decrypt(&bm)
}

func (d *HybridDecrypter) decrypt(bm *hybridBoxedMessage) ([]byte, error) {
	ephemeralX25519Public, err := ecdh.X25519().NewPublicKey(bm.EphemeralX25519Public[:])
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	x25519SharedSecret, err := d.x25519Private.ECDH(ephemeralX25519Public)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	mlkemSharedSecret, err := d.mlkemPrivate.Decapsulate(bm.MLKEMCiphertext[:])
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	key, aad, err := deriveHybridAEADKeyAndAAD(d.PrivateKey.Public, bm.EphemeralX25519Public[:], bm.MLKEMCiphertext[:], x25519SharedSecret, mlkemSharedSecret)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := aead.Open(nil, bm.Nonce[:], bm.Box, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func (b *hybridBoxedMessage) Dump() []byte {
	epk := base64.StdEncoding.EncodeToString(b.EphemeralX25519Public[:])
	kemCiphertext := base64.StdEncoding.EncodeToString(b.MLKEMCiphertext[:])
	nonce := base64.StdEncoding.EncodeToString(b.Nonce[:])
	box := base64.StdEncoding.EncodeToString(b.Box)

	return []byte(fmt.Sprintf("EJ[%d:%s:%s:%s:%s]", b.SchemaVersion, epk, kemCiphertext, nonce, box))
}

func (b *hybridBoxedMessage) Load(from []byte) error {
	version, fields, err := parseBoxedEnvelope(from)
	if err != nil {
		return err
	}
	if version != SchemaVersionHybrid || len(fields) != 4 {
		return fmt.Errorf("invalid message format")
	}
	b.SchemaVersion = version

	ephemeralPublic, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return err
	}
	if len(ephemeralPublic) != hybridX25519KeySize {
		return fmt.Errorf("public key invalid")
	}
	copy(b.EphemeralX25519Public[:], ephemeralPublic)

	mlkemCiphertext, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return err
	}
	if len(mlkemCiphertext) != hybridMLKEMCiphertextSize {
		return fmt.Errorf("ML-KEM ciphertext invalid")
	}
	copy(b.MLKEMCiphertext[:], mlkemCiphertext)

	nonce, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("nonce invalid")
	}
	copy(b.Nonce[:], nonce)

	box, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		return err
	}
	b.Box = []byte(box)
	return nil
}

func deriveHybridAEADKeyAndAAD(recipientPublic HybridPublicKey, ephemeralX25519Public, mlkemCiphertext, x25519SharedSecret, mlkemSharedSecret []byte) (key []byte, aad []byte, err error) {
	if len(ephemeralX25519Public) != hybridX25519KeySize || len(mlkemCiphertext) != hybridMLKEMCiphertextSize || len(x25519SharedSecret) != hybridX25519KeySize || len(mlkemSharedSecret) != mlkem.SharedKeySize {
		return nil, nil, fmt.Errorf("invalid hybrid key material")
	}

	ikm := make([]byte, 0, len(x25519SharedSecret)+len(mlkemSharedSecret))
	ikm = append(ikm, x25519SharedSecret...)
	ikm = append(ikm, mlkemSharedSecret...)

	aad = hybridTranscript(recipientPublic, ephemeralX25519Public, mlkemCiphertext)
	key, err = hkdf.Key(sha256.New, ikm, []byte(hybridKDFSalt), string(aad), chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	return key, aad, nil
}

func hybridTranscript(recipientPublic HybridPublicKey, ephemeralX25519Public, mlkemCiphertext []byte) []byte {
	out := make([]byte, 0, len(hybridAADDomain)+1+len(ephemeralX25519Public)+len(recipientPublic.X25519Public)+len(recipientPublic.MLKEMEncapsulationKey)+len(mlkemCiphertext))
	out = append(out, hybridAADDomain...)
	out = append(out, 0)
	out = append(out, ephemeralX25519Public...)
	out = append(out, recipientPublic.X25519Public[:]...)
	out = append(out, recipientPublic.MLKEMEncapsulationKey[:]...)
	out = append(out, mlkemCiphertext...)
	return out
}
