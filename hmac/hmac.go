package hmac

import (
	"crypto/hmac"
	"crypto/sha512"
)

//	Generates a symmetric signature using a shared secret key
func Generate(data []byte, key [32]byte) []byte {
	h := hmac.New(sha512.New512_256, key[:])
	h.Write(data)
	return h.Sum(nil)
}

//	Securely check the givenMAC against the data with the shared secret key
func Verify(data, givenMAC []byte, key [32]byte) bool {
	expectedMAC := Generate(data, key)
	return hmac.Equal(givenMAC, expectedMAC)
}
