package utils

import (
	"encoding/base64"
	"encoding/hex"
)

//	Encodes a byte slice to a base64 string.
func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

//	Decodes a base64 string to a byte slice.
func DecodeBase64(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return data, nil
}

//	Encodes a byte slice to a hex string.
func EncodeHex(b []byte) string {
	return hex.EncodeToString(b)
}

//	Decodes a hex string to a byte slice.
func DecodeHex(s string) ([]byte, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return data, nil
}
