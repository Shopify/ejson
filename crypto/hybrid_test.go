package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestHybridKeypairGenerationAndParsing(t *testing.T) {
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub.String(), "v3:") {
		t.Fatalf("hybrid public key should have v3 prefix: %q", pub.String()[:3])
	}
	if len(pub.KeyID()) != 32 {
		t.Fatalf("hybrid key ID should be 32 hex chars, got %d", len(pub.KeyID()))
	}

	parsedPub, err := ParsePublicKeyString(pub.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsedPub.Version() != SchemaVersionHybrid {
		t.Fatalf("parsed public key version = %d, want %d", parsedPub.Version(), SchemaVersionHybrid)
	}
	if parsedPub.String() != pub.String() {
		t.Fatal("parsed public key did not roundtrip")
	}

	parsedPriv, err := ParsePrivateKeyForPublic(parsedPub, []byte(priv.String()))
	if err != nil {
		t.Fatal(err)
	}
	if parsedPriv.Version() != SchemaVersionHybrid {
		t.Fatalf("parsed private key version = %d, want %d", parsedPriv.Version(), SchemaVersionHybrid)
	}

	enc, err := NewMessageEncrypter(parsedPub)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewMessageDecrypter(parsedPub, parsedPriv)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := dec.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "secret" {
		t.Fatalf("plaintext = %q, want secret", pt)
	}
}

func TestHybridRoundtripAndNoReencrypt(t *testing.T) {
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewMessageEncrypter(pub)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewMessageDecrypter(pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	messages := [][]byte{
		[]byte(""),
		[]byte("This is a test of the post-quantum emergency broadcast system."),
		bytes.Repeat([]byte("0123456789abcdef"), 640),
	}
	for _, message := range messages {
		ct, err := enc.Encrypt(message)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(ct, []byte("EJ[3:")) {
			t.Fatalf("ciphertext prefix = %.5q, want EJ[3:", ct)
		}
		if !IsBoxedMessage(ct) {
			t.Fatalf("v3 ciphertext was not recognized as boxed: %.32q", ct)
		}
		ct2, err := enc.Encrypt(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ct2, ct) {
			t.Fatal("already boxed v3 message was re-encrypted")
		}

		pt, err := dec.Decrypt(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, message) {
			t.Fatal("plaintext did not roundtrip")
		}
	}
}

func TestHybridRejectsWrongKeyAndTampering(t *testing.T) {
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, wrongPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewMessageEncrypter(pub)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewMessageDecrypter(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	wrongDec, err := NewMessageDecrypter(wrongPub, wrongPriv)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.Encrypt([]byte("swordfish"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongDec.Decrypt(ct); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}

	mutations := map[string]func(*hybridBoxedMessage){
		"ephemeral X25519 public key": func(bm *hybridBoxedMessage) { bm.EphemeralX25519Public[0] ^= 0x80 },
		"ML-KEM ciphertext":           func(bm *hybridBoxedMessage) { bm.MLKEMCiphertext[0] ^= 0x80 },
		"nonce":                       func(bm *hybridBoxedMessage) { bm.Nonce[0] ^= 0x80 },
		"AEAD ciphertext":             func(bm *hybridBoxedMessage) { bm.Box[0] ^= 0x80 },
	}
	for name, mutate := range mutations {
		var bm hybridBoxedMessage
		if err := bm.Load(ct); err != nil {
			t.Fatal(err)
		}
		mutate(&bm)
		if _, err := dec.Decrypt(bm.Dump()); err == nil {
			t.Fatalf("decrypt succeeded after tampering with %s", name)
		}
	}
}

func TestHybridRejectsKEMCiphertextSplicing(t *testing.T) {
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewMessageEncrypter(pub)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewMessageDecrypter(pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	ct1, err := enc.Encrypt([]byte("first secret"))
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := enc.Encrypt([]byte("second secret"))
	if err != nil {
		t.Fatal(err)
	}

	var bm1, bm2 hybridBoxedMessage
	if err := bm1.Load(ct1); err != nil {
		t.Fatal(err)
	}
	if err := bm2.Load(ct2); err != nil {
		t.Fatal(err)
	}
	bm1.MLKEMCiphertext = bm2.MLKEMCiphertext

	if _, err := dec.Decrypt(bm1.Dump()); err == nil {
		t.Fatal("decrypt succeeded after ML-KEM ciphertext splice")
	}
}

func TestHybridPrivateKeyRejectsMismatchedPublicKey(t *testing.T) {
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParsePrivateKeyForPublic(pub, []byte(otherPriv.String())); err == nil {
		t.Fatal("mismatched v3 private key parsed successfully")
	}
}

func TestHybridPublicKeyRejectsInvalidInputs(t *testing.T) {
	if _, err := ParsePublicKeyString("v3:not base64"); err == nil {
		t.Fatal("invalid base64 v3 public key parsed successfully")
	}
	if _, err := ParsePublicKeyString("v3:" + strings.Repeat("A", 16)); err == nil {
		t.Fatal("short v3 public key parsed successfully")
	}
}
