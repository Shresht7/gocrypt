package hash

import (
	"crypto/hmac"
	"crypto/sha512"
)

//	Hash data using HMAC-SHA-512/256.
//	This algorithm is fast on 64-bit machines and immune to length-extension attacks.
//	The tag signifies the purpose of the hash
//	and ensures that different purposes produce different hashes even with the same data.
func HMAC_SHA_512_256(data []byte, tag string) ([]byte, error) {
	return Hash(data, hmac.New(sha512.New512_256, []byte(tag)))
}
