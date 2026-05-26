package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	SchemaVersionLegacy = 1
	SchemaVersionHybrid = 3

	SchemeLegacy = "v1"
	SchemeHybrid = "v3"

	hybridPublicKeyPrefix = "v3:"
	hybridKeyFileHeader   = "ejson-key v3"
	hybridKeyIDDomain     = "ejson/v3/pubkey"
)

const (
	hybridX25519KeySize        = 32
	hybridMLKEMSeedSize        = mlkem.SeedSize
	hybridMLKEMPublicKeySize   = mlkem.EncapsulationKeySize768
	hybridMLKEMCiphertextSize  = mlkem.CiphertextSize768
	hybridPublicKeyPayloadSize = hybridX25519KeySize + hybridMLKEMPublicKeySize
)

// PublicKey is a schema-aware ejson public key.
type PublicKey interface {
	Version() int
	String() string
	KeyID() string
}

// PrivateKey is a schema-aware ejson private key.
type PrivateKey interface {
	Version() int
	String() string
}

// MessageEncrypter encrypts individual JSON string values.
type MessageEncrypter interface {
	Encrypt([]byte) ([]byte, error)
}

// MessageDecrypter decrypts individual JSON string values.
type MessageDecrypter interface {
	Decrypt([]byte) ([]byte, error)
}

// LegacyPublicKey is the v1 32-byte Curve25519 public key.
type LegacyPublicKey struct {
	Key [32]byte
}

func (k LegacyPublicKey) Version() int { return SchemaVersionLegacy }
func (k LegacyPublicKey) String() string {
	return hex.EncodeToString(k.Key[:])
}
func (k LegacyPublicKey) KeyID() string { return k.String() }

// LegacyPrivateKey is the v1 32-byte Curve25519 private key.
type LegacyPrivateKey struct {
	Key [32]byte
}

func (k LegacyPrivateKey) Version() int { return SchemaVersionLegacy }
func (k LegacyPrivateKey) String() string {
	return hex.EncodeToString(k.Key[:])
}

// HybridPublicKey is a v3 X25519 + ML-KEM-768 public key.
type HybridPublicKey struct {
	X25519Public          [hybridX25519KeySize]byte
	MLKEMEncapsulationKey [hybridMLKEMPublicKeySize]byte
}

func (k HybridPublicKey) Version() int { return SchemaVersionHybrid }
func (k HybridPublicKey) String() string {
	return hybridPublicKeyPrefix + base64.StdEncoding.EncodeToString(k.Bytes())
}
func (k HybridPublicKey) KeyID() string {
	h := sha256.New()
	_, _ = h.Write([]byte(hybridKeyIDDomain))
	_, _ = h.Write(k.X25519Public[:])
	_, _ = h.Write(k.MLKEMEncapsulationKey[:])
	return hex.EncodeToString(h.Sum(nil)[:16])
}
func (k HybridPublicKey) Bytes() []byte {
	out := make([]byte, 0, hybridPublicKeyPayloadSize)
	out = append(out, k.X25519Public[:]...)
	out = append(out, k.MLKEMEncapsulationKey[:]...)
	return out
}

// HybridPrivateKey is a v3 X25519 + ML-KEM-768 private key.
type HybridPrivateKey struct {
	Public        HybridPublicKey
	X25519Private [hybridX25519KeySize]byte
	MLKEMSeed     [hybridMLKEMSeedSize]byte
}

func (k HybridPrivateKey) Version() int { return SchemaVersionHybrid }
func (k HybridPrivateKey) String() string {
	return strings.Join([]string{
		hybridKeyFileHeader,
		"keyid: " + k.Public.KeyID(),
		"pub-x25519: " + hex.EncodeToString(k.Public.X25519Public[:]),
		"pub-mlkem768: " + base64.StdEncoding.EncodeToString(k.Public.MLKEMEncapsulationKey[:]),
		"priv-x25519: " + hex.EncodeToString(k.X25519Private[:]),
		"priv-mlkem768-seed: " + hex.EncodeToString(k.MLKEMSeed[:]),
	}, "\n")
}

// ParsePublicKeyString parses a public key in ejson document form. Legacy v1
// keys are bare 64-character hex strings. Hybrid v3 keys are v3:<base64>.
func ParsePublicKeyString(s string) (PublicKey, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, hybridPublicKeyPrefix) {
		return ParseHybridPublicKeyString(s)
	}
	return ParseLegacyPublicKeyString(s)
}

// ParseLegacyPublicKeyString parses a legacy v1 public key.
func ParseLegacyPublicKeyString(s string) (LegacyPublicKey, error) {
	var key LegacyPublicKey
	if len(s) != 64 {
		return key, fmt.Errorf("public key invalid")
	}
	bs, err := hex.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("public key invalid")
	}
	if len(bs) != len(key.Key) {
		return key, fmt.Errorf("public key invalid")
	}
	copy(key.Key[:], bs)
	return key, nil
}

// ParseHybridPublicKeyString parses a v3 hybrid public key.
func ParseHybridPublicKeyString(s string) (HybridPublicKey, error) {
	var key HybridPublicKey
	if !strings.HasPrefix(s, hybridPublicKeyPrefix) {
		return key, fmt.Errorf("public key invalid")
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, hybridPublicKeyPrefix))
	if err != nil {
		return key, fmt.Errorf("public key invalid")
	}
	return NewHybridPublicKey(payload)
}

// NewHybridPublicKey validates and constructs a v3 hybrid public key from raw
// pk_x25519 || ek_mlkem768 bytes.
func NewHybridPublicKey(payload []byte) (HybridPublicKey, error) {
	var key HybridPublicKey
	if len(payload) != hybridPublicKeyPayloadSize {
		return key, fmt.Errorf("public key invalid")
	}

	x25519Public := payload[:hybridX25519KeySize]
	mlkemPublic := payload[hybridX25519KeySize:]
	if _, err := ecdh.X25519().NewPublicKey(x25519Public); err != nil {
		return key, fmt.Errorf("public key invalid")
	}
	if _, err := mlkem.NewEncapsulationKey768(mlkemPublic); err != nil {
		return key, fmt.Errorf("public key invalid")
	}

	copy(key.X25519Public[:], x25519Public)
	copy(key.MLKEMEncapsulationKey[:], mlkemPublic)
	return key, nil
}

// GenerateKeypairForScheme generates a v1 or v3 ejson keypair.
func GenerateKeypairForScheme(scheme string) (PublicKey, PrivateKey, error) {
	switch normalizeScheme(scheme) {
	case SchemeLegacy:
		var kp Keypair
		if err := kp.Generate(); err != nil {
			return nil, nil, err
		}
		return LegacyPublicKey{Key: kp.Public}, LegacyPrivateKey{Key: kp.Private}, nil
	case SchemeHybrid:
		return GenerateHybridKeypair()
	default:
		return nil, nil, fmt.Errorf("unsupported key scheme %q", scheme)
	}
}

// GenerateHybridKeypair generates a v3 X25519 + ML-KEM-768 keypair.
func GenerateHybridKeypair() (HybridPublicKey, HybridPrivateKey, error) {
	var pub HybridPublicKey
	var priv HybridPrivateKey

	x25519Private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return pub, priv, err
	}
	x25519Public := x25519Private.PublicKey().Bytes()

	mlkemPrivate, err := mlkem.GenerateKey768()
	if err != nil {
		return pub, priv, err
	}
	mlkemSeed := mlkemPrivate.Bytes()
	mlkemPublic := mlkemPrivate.EncapsulationKey().Bytes()

	copy(pub.X25519Public[:], x25519Public)
	copy(pub.MLKEMEncapsulationKey[:], mlkemPublic)
	priv.Public = pub
	copy(priv.X25519Private[:], x25519Private.Bytes())
	copy(priv.MLKEMSeed[:], mlkemSeed)
	return pub, priv, nil
}

// ParsePrivateKeyForPublic parses private key material for the corresponding
// public key and verifies that v3 keyfiles match the public key.
func ParsePrivateKeyForPublic(pub PublicKey, data []byte) (PrivateKey, error) {
	switch p := pub.(type) {
	case LegacyPublicKey:
		return parseLegacyPrivateKey(data)
	case HybridPublicKey:
		return parseHybridPrivateKeyForPublic(p, data)
	default:
		return nil, fmt.Errorf("unsupported key scheme")
	}
}

// NewMessageEncrypter returns an encrypter for the given schema-aware public key.
func NewMessageEncrypter(pub PublicKey) (MessageEncrypter, error) {
	switch p := pub.(type) {
	case LegacyPublicKey:
		var kp Keypair
		if err := kp.Generate(); err != nil {
			return nil, err
		}
		return kp.Encrypter(p.Key), nil
	case HybridPublicKey:
		return NewHybridEncrypter(p)
	default:
		return nil, fmt.Errorf("unsupported key scheme")
	}
}

// NewMessageDecrypter returns a decrypter for the given schema-aware keypair.
func NewMessageDecrypter(pub PublicKey, priv PrivateKey) (MessageDecrypter, error) {
	if pub.Version() != priv.Version() {
		return nil, fmt.Errorf("private key does not match public key")
	}

	switch p := pub.(type) {
	case LegacyPublicKey:
		legacyPriv, ok := priv.(LegacyPrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key does not match public key")
		}
		kp := Keypair{Public: p.Key, Private: legacyPriv.Key}
		return kp.Decrypter(), nil
	case HybridPublicKey:
		hybridPriv, ok := priv.(HybridPrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key does not match public key")
		}
		if hybridPriv.Public.String() != p.String() {
			return nil, fmt.Errorf("private key does not match public key")
		}
		return NewHybridDecrypter(hybridPriv)
	default:
		return nil, fmt.Errorf("unsupported key scheme")
	}
}

func parseLegacyPrivateKey(data []byte) (LegacyPrivateKey, error) {
	var key LegacyPrivateKey
	bs, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return key, err
	}
	if len(bs) != len(key.Key) {
		return key, fmt.Errorf("invalid private key")
	}
	copy(key.Key[:], bs)
	return key, nil
}

func parseHybridPrivateKeyForPublic(expected HybridPublicKey, data []byte) (HybridPrivateKey, error) {
	fields, err := parseHybridPrivateKeyFields(data)
	if err != nil {
		return HybridPrivateKey{}, err
	}

	keyID := fields["keyid"]
	pubXString := fields["pub-x25519"]
	pubMLKEMString := fields["pub-mlkem768"]
	privXString := fields["priv-x25519"]
	seedString := fields["priv-mlkem768-seed"]
	if keyID == "" || pubXString == "" || pubMLKEMString == "" || privXString == "" || seedString == "" {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}

	pubX, err := hex.DecodeString(pubXString)
	if err != nil || len(pubX) != hybridX25519KeySize {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	pubMLKEM, err := base64.StdEncoding.DecodeString(pubMLKEMString)
	if err != nil || len(pubMLKEM) != hybridMLKEMPublicKeySize {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	payload := append(append([]byte{}, pubX...), pubMLKEM...)
	public, err := NewHybridPublicKey(payload)
	if err != nil {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	if keyID != public.KeyID() || public.String() != expected.String() {
		return HybridPrivateKey{}, fmt.Errorf("private key does not match public key")
	}

	privX, err := hex.DecodeString(privXString)
	if err != nil || len(privX) != hybridX25519KeySize {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	x25519Private, err := ecdh.X25519().NewPrivateKey(privX)
	if err != nil {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	if !bytes.Equal(x25519Private.PublicKey().Bytes(), public.X25519Public[:]) {
		return HybridPrivateKey{}, fmt.Errorf("private key does not match public key")
	}

	seed, err := hex.DecodeString(seedString)
	if err != nil || len(seed) != hybridMLKEMSeedSize {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	mlkemPrivate, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return HybridPrivateKey{}, fmt.Errorf("invalid private key")
	}
	if !bytes.Equal(mlkemPrivate.EncapsulationKey().Bytes(), public.MLKEMEncapsulationKey[:]) {
		return HybridPrivateKey{}, fmt.Errorf("private key does not match public key")
	}

	var private HybridPrivateKey
	private.Public = public
	copy(private.X25519Private[:], privX)
	copy(private.MLKEMSeed[:], seed)
	return private, nil
}

func parseHybridPrivateKeyFields(data []byte) (map[string]string, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != hybridKeyFileHeader {
		return nil, fmt.Errorf("invalid private key")
	}

	fields := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid private key")
		}
		fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return fields, nil
}

func normalizeScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "", "1", SchemeLegacy, "legacy", "classic", "nacl", "box":
		return SchemeLegacy
	case "3", SchemeHybrid, "hybrid", "pqc", "post-quantum", "postquantum", "mlkem", "ml-kem":
		return SchemeHybrid
	default:
		return strings.ToLower(strings.TrimSpace(scheme))
	}
}
