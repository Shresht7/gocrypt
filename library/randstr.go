package library

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
)

//	Generates n random bytes
func GenerateBytes(n int) []byte {
	b := make([]byte, n)

	_, err := rand.Read(b)
	Check(err)

	return b
}

const NUMBERS = "1234567890"
const LOWERCASE_ALPHABETS = "abcdefghijklmnopqrstuvwxyz"
const UPPERCASE_ALPHABETS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const ALPHABETS = LOWERCASE_ALPHABETS + UPPERCASE_ALPHABETS
const CHARSET = NUMBERS + ALPHABETS

//	Generates a random string using the given charset.
//	If no charset is provided, uses the default charset (alphanumeric).
func GenerateString(n int, charset ...string) string {
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
		bytesBuffer.WriteRune(
			runes[binary.BigEndian.Uint32(GenerateBytes(4))%length],
		)
	}

	return bytesBuffer.String()
}

//	Generates a random base64 string of length n
func GenerateBase64(n int) string {
	return GenerateString(n, CHARSET+"+/")
}

//	Generates a random hex of length n
func GenerateHex(n int) string {
	return hex.EncodeToString(GenerateBytes(n))
}
