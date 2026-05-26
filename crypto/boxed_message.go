package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	boxedMessagePrefix = "EJ["
	boxedMessageSuffix = "]"
)

// boxedMessage dumps and loads the v1 wire format for encrypted messages. The
// schema is fairly simple:
//
//	"EJ["
//	SchemaVersion ( "1" )
//	":"
//	EncrypterPublic :: base64-encoded 32-byte key
//	":"
//	Nonce :: base64-encoded 24-byte nonce
//	":"
//	Box :: base64-encoded encrypted message
//	"]"
type boxedMessage struct {
	SchemaVersion   int
	EncrypterPublic [32]byte
	Nonce           [24]byte
	Box             []byte
}

// IsBoxedMessage tests whether a value is formatted using a supported boxed
// message format. This can be used to determine whether a string value requires
// encryption or is already encrypted.
func IsBoxedMessage(data []byte) bool {
	version, fields, err := parseBoxedEnvelope(data)
	if err != nil {
		return false
	}

	switch version {
	case SchemaVersionLegacy:
		return len(fields) == 3 && len(fields[0]) == base64.StdEncoding.EncodedLen(32) && len(fields[1]) == base64.StdEncoding.EncodedLen(24) && fields[2] != ""
	case SchemaVersionHybrid:
		return len(fields) == 4 && len(fields[0]) == base64.StdEncoding.EncodedLen(32) && len(fields[1]) == base64.StdEncoding.EncodedLen(hybridMLKEMCiphertextSize) && len(fields[2]) == base64.StdEncoding.EncodedLen(24) && fields[3] != ""
	default:
		return false
	}
}

// Dump dumps to the v1 wire format.
func (b *boxedMessage) Dump() []byte {
	pub := base64.StdEncoding.EncodeToString(b.EncrypterPublic[:])
	nonce := base64.StdEncoding.EncodeToString(b.Nonce[:])
	box := base64.StdEncoding.EncodeToString(b.Box)

	str := fmt.Sprintf("EJ[%d:%s:%s:%s]",
		b.SchemaVersion, pub, nonce, box)
	return []byte(str)
}

// Load restores from the v1 wire format.
func (b *boxedMessage) Load(from []byte) error {
	version, fields, err := parseBoxedEnvelope(from)
	if err != nil {
		return err
	}
	if version != SchemaVersionLegacy || len(fields) != 3 {
		return fmt.Errorf("invalid message format")
	}
	b.SchemaVersion = version

	pub, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return err
	}
	if len(pub) != 32 {
		return fmt.Errorf("public key invalid")
	}
	copy(b.EncrypterPublic[:], pub)

	nnc, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return err
	}
	if len(nnc) != 24 {
		return fmt.Errorf("nonce invalid")
	}
	copy(b.Nonce[:], nnc)

	box, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return err
	}
	b.Box = []byte(box)

	return nil
}

func parseBoxedEnvelope(data []byte) (version int, fields []string, err error) {
	message := string(data)
	if !strings.HasPrefix(message, boxedMessagePrefix) || !strings.HasSuffix(message, boxedMessageSuffix) {
		return 0, nil, fmt.Errorf("invalid message format")
	}

	body := strings.TrimSuffix(strings.TrimPrefix(message, boxedMessagePrefix), boxedMessageSuffix)
	versionString, rest, ok := strings.Cut(body, ":")
	if !ok || versionString == "" || rest == "" {
		return 0, nil, fmt.Errorf("invalid message format")
	}

	version, err = strconv.Atoi(versionString)
	if err != nil {
		return 0, nil, err
	}

	return version, strings.Split(rest, ":"), nil
}
