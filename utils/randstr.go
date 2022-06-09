package utils

import (
	"bytes"
	"encoding/binary"
)

//	Character Sets
const (
	NUMBERS             = "1234567890"
	LOWERCASE_ALPHABETS = "abcdefghijklmnopqrstuvwxyz"
	UPPERCASE_ALPHABETS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ALPHABETS           = LOWERCASE_ALPHABETS + UPPERCASE_ALPHABETS
	CHARSET             = NUMBERS + ALPHABETS
)

//	Generates a random string using the given charset.
//	If no charset is provided, uses the default charset (alphanumeric).
func GenerateString(n int, charset ...string) (string, error) {

	//	Runes to use to generate strings
	var runes []rune
	if len(charset) != 0 {
		//	If the user provides a character set, use it
		runes = []rune(charset[0])
	} else {
		//	Otherwise, use the default character set
		runes = []rune(CHARSET)
	}

	//	Create a byte buffer to store the string
	var bytesBuffer bytes.Buffer
	bytesBuffer.Grow(n) //	Pre-allocate the buffer

	//	Generate the string
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
	return EncodeHex(bytes), nil
}
