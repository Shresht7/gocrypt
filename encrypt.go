package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/Shresht7/gocrypt/library"
)

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

//	Encrypt the given text
func Encrypt(text, secret string) (string, error) {

	//	Generate Cipher Block
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	plainText := []byte(text)
	cipherText := make([]byte, len(plainText))

	//	Generate Initialization Vector using the appropriate block size
	initializationVector := library.GenerateBytes(block.BlockSize())

	//	Encrypter Stream
	CFBEncrypter := cipher.NewCFBEncrypter(block, initializationVector)

	//	Encrypt plainText into cipherText
	CFBEncrypter.XORKeyStream(cipherText, plainText)

	//	Append Initialization Vector to the end of the cipherText
	cipherText = append(cipherText, initializationVector...)

	return Encode(cipherText), nil
}
