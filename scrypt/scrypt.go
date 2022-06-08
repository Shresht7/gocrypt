package scrypt

import (
	"github.com/Shresht7/gocrypt/library"
	"golang.org/x/crypto/scrypt"
)

func HashPassword_scrypt(password []byte) ([]byte, error) {
	salt, err := library.GenerateBytes(32)
	if err != nil {
		panic(err)
	}
	N := 32768
	r := 8
	p := 1
	keyLen := 32
	return scrypt.Key(password, salt, N, r, p, keyLen)
}
