package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"

	"github.com/Shresht7/gocrypt/library"
)

//	Encrypt the given text
func Encrypt(text string, secret string) (string, error) {

	//	Generate Key from Secret using HMAC
	key, err := Hash([]byte(secret), hmac.New(sha512.New512_256, []byte(secret)))
	if err != nil {
		return "", err
	}

	//	Generate Cipher Block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	//	Generate Nonce
	nonce, err := library.GenerateBytes(gcm.NonceSize())
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)

	//	Seal the text
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return library.EncodeBase64(ciphertext), nil

}
