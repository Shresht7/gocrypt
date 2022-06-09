package utils

import "crypto/rand"

//	Generates n random bytes with capacity
func GenerateBytes(size int, capacity ...int) ([]byte, error) {

	//	If capacity is lower than size, use size as capacity
	if capacity[0] < size {
		capacity[0] = size
	}

	//	Create the byte slice
	b := make([]byte, size, capacity[0])

	_, err := rand.Read(b)
	if err != nil {
		panic(err) //	Panics on errors as key generation is critical
	}

	return b, nil
}
