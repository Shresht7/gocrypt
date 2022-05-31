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

	//	Generate Initialization Vector using the appropriate block size
	initializationVector := library.GenerateBytes(block.BlockSize())

	//	Encrypter Stream
	CFBEncrypter := cipher.NewCFBEncrypter(block, initializationVector)

	plainText := []byte(text)
	cipherText := make([]byte, len(plainText))

	//	Encrypt plainText into cipherText
	CFBEncrypter.XORKeyStream(cipherText, plainText)

	return Encode(cipherText), nil
}
