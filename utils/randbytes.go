package utils

import (
	"crypto/rand"
	"errors"
)

//	Generate a random byte slice of the given size
func GenerateBytes(size int) ([]byte, error) {
	return generateBytes(size, size)
}

//	Generate a random byte slice of the given size and capacity
func GenerateBytesWithCapacity(size, capacity int) ([]byte, error) {
	return generateBytes(size, capacity)
}

//	Generate a random byte slice of the given size and capacity
func generateBytes(size, capacity int) ([]byte, error) {

	// Check if capacity is greater than size
	if capacity < size {
		return nil, errors.New("capacity must be greater than size")
	}

	//	Create the byte slice
	b := make([]byte, size, capacity)

	//	Read the cryptographically secure random bytes
	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil

}
