package hash

import "crypto/sha256"

//	Hash data using the SHA-256 algorithm
func SHA256(s []byte) ([]byte, error) {
	return Hash(s, sha256.New())
}
