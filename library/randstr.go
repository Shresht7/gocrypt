package library

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
)

//	Generates n random bytes
func GenerateBytes(n int) ([]byte, error) {
	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

const NUMBERS = "1234567890"
const LOWERCASE_ALPHABETS = "abcdefghijklmnopqrstuvwxyz"
const UPPERCASE_ALPHABETS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const ALPHABETS = LOWERCASE_ALPHABETS + UPPERCASE_ALPHABETS
const CHARSET = NUMBERS + ALPHABETS

//	Generates a random string using the given charset.
//	If no charset is provided, uses the default charset (alphanumeric).
func GenerateString(n int, charset ...string) (string, error) {
	var runes []rune
	if len(charset) == 0 {
		runes = []rune(CHARSET)
	} else {
		runes = []rune(charset[0])
	}

	var bytesBuffer bytes.Buffer
	bytesBuffer.Grow(n)

	length := uint32(len(runes))
	for i := 0; i < n; i++ {
		bytes, err := GenerateBytes(4)
		if err != nil {
			return "", err
		}
		bytesBuffer.WriteRune(
			runes[binary.BigEndian.Uint32(bytes)%length],
		)
	}

	return bytesBuffer.String(), nil
}

//	Generates a random base64 string of length n
func GenerateBase64(n int) (string, error) {
	return GenerateString(n, CHARSET+"+/")
}

//	Generates a random hex of length n
func GenerateHex(n int) (string, error) {
	bytes, err := GenerateBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
