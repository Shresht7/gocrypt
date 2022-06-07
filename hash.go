package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/bcrypt"
)

//	Hash data using the SHA-256 algorithm
func Hash_sha256(s []byte) ([]byte, error) {
	return Hash(s, sha256.New())
}

//	Hash data using HMAC-SHA-512/256.
//	This algorithm is fast on 64-bit machines and immune to length-extension attacks.
//	The tag signifies the purpose of the hash
//	and ensures that different purposes produce different hashes even with the same data.
func Hash_hmac_sha_512_256(s []byte, tag string) ([]byte, error) {
	return Hash(s, hmac.New(sha512.New512_256, []byte(tag)))
}

//	Hash the data using the given Hash
func Hash(s []byte, h hash.Hash) ([]byte, error) {
	_, err := h.Write(s)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

const WORK_FACTOR = 14

//	Hashes the password using bcrypt
func HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, WORK_FACTOR)
}

//	Verify the password with the given hash. Returns error on failure.
func VerifyPassword(password, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
