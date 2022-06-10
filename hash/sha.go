package hash

import (
	"crypto/sha256"
	"crypto/sha512"
)

//	Hash data using the SHA-256 algorithm
func SHA256(data []byte) ([]byte, error) {
	return Hash(data, sha256.New())
}

//	Hash data using the SHA-512 algorithm
func SHA512(data []byte) ([]byte, error) {
	return Hash(data, sha512.New())
}
