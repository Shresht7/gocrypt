package main

import (
	"crypto/hmac"
	"crypto/sha512"
)

//	Generates a symmetric signature using a shared secret key
func GenerateHMAC(data []byte, key [32]byte) []byte {
	h := hmac.New(sha512.New512_256, key[:])
	h.Write(data)
	return h.Sum(nil)
}

//	Securely check the givenMAC against the data with the shared secret key
func VerifyHMAC(data, givenMAC []byte, key [32]byte) bool {
	expectedMAC := GenerateHMAC(data, key)
	return hmac.Equal(givenMAC, expectedMAC)
}
