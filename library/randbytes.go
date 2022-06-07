package library

import "crypto/rand"

//	Generates n random bytes
func GenerateBytes(size int) ([]byte, error) {
	b := make([]byte, size)

	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil
}
