package library

import "crypto/rand"

//	Generates n random bytes with capacity
func GenerateBytes(size int) ([]byte, error) {
	b := make([]byte, size)

	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil
}

//	Generates n random bytes with capacity
func GenerateBytesWithCapacity(size, capacity int) ([]byte, error) {
	if capacity < size {
		capacity = size
	}

	b := make([]byte, size, capacity)

	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil
}
