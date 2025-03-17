package util

import (
	"crypto/sha256"
	"encoding/base64"
	"unsafe"
)

const HashSize = sha256.Size

var Base64SHA256Length = base64.StdEncoding.EncodedLen(HashSize)

func SHA256String(entity string) [HashSize]byte {
	return sha256.Sum256(unsafe.Slice(unsafe.StringData(entity), len(entity)))
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
