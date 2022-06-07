package main

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/Shresht7/gocrypt/library"
)

func Decrypt(text, secret string) (string, error) {

	//	Generate Key from Secret
	key := Hash([]byte(secret))

	//	Generate Decipher Block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText, err := library.DecodeBase64(text)
	if err != nil {
		return "", err
	}
	plainText := make([]byte, len(cipherText))

	//	Extract Initialization Vector
	initializationVector := cipherText[len(cipherText)-block.BlockSize():]
	cipherText = cipherText[:len(cipherText)-block.BlockSize()]

	//	Decrypter Stream
	CFBDecrypter := cipher.NewCFBDecrypter(block, initializationVector)

	//	Decrypt cipherText into plainText
	CFBDecrypter.XORKeyStream(plainText, cipherText)

	return string(plainText), nil

}
