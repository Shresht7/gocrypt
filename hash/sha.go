package hash

import (
	"crypto/sha256"
	"crypto/sha512"
)

//	Hash data using the SHA-256 algorithm
func SHA256(s []byte) ([]byte, error) {
	return Hash(s, sha256.New())
}

//	Hash data using the SHA-512 algorithm
func SHA512(s []byte) ([]byte, error) {
	return Hash(s, sha512.New())
}
