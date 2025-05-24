package util

import (
	"crypto/sha256"
	"encoding/base64"

	"go.mau.fi/util/exstrings"
)

const HashSize = sha256.Size

var Base64SHA256Length = base64.StdEncoding.EncodedLen(HashSize)

func SHA256String[T ~string](entity T) [HashSize]byte {
	return sha256.Sum256(exstrings.UnsafeBytes(string(entity)))
}

func DecodeBase64Hash(hash string) (*[HashSize]byte, bool) {
	if len(hash) != Base64SHA256Length {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return nil, false
	}
	return (*[HashSize]byte)(decoded), true
}
