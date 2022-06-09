package utils

import "crypto/rand"

//	Generates n random bytes with with given size
func GenerateBytes(size int) ([]byte, error) {

	//	Create the byte slice
	b := make([]byte, size)

	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil

}

//	Generates n random bytes with with given size and given capacity
func GenerateBytesWithCapacity(size, capacity int) ([]byte, error) {

	//	Create the byte slice
	b := make([]byte, size, capacity)

	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil

}
