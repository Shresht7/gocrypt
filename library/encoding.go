package library

import (
	"encoding/base64"
	"encoding/hex"
)

func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeBase64(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func EncodeHex(b []byte) string {
	return hex.EncodeToString(b)
}

func DecodeHex(s string) ([]byte, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return data, nil
}
