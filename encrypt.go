package main

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/Shresht7/gocrypt/library"
)

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
	initializationVector, err := library.GenerateBytes(block.BlockSize())
	if err != nil {
		return "", err
	}

	//	Encrypter Stream
	CFBEncrypter := cipher.NewCFBEncrypter(block, initializationVector)

	//	Encrypt plainText into cipherText
	CFBEncrypter.XORKeyStream(cipherText, plainText)

	//	Append Initialization Vector to the end of the cipherText
	cipherText = append(cipherText, initializationVector...)

	return library.Encode(cipherText), nil
}
