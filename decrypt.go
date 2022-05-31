package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func Decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func Decrypt(text, secret string) (string, error) {

	//	Generate Decipher Block
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	cipherText, err := Decode(text)
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
