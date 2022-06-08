//	Provides symmetric authenticated encryption using AES-GCM-256 AEAD
package aes_gcm_256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"

	"github.com/Shresht7/gocrypt/hash"
	"github.com/Shresht7/gocrypt/library"
)

//	Encrypt the given text
func Encrypt(text string, secret string) (string, error) {

	//	Generate Key from Secret using HMAC
	key, err := hash.Hash([]byte(secret), hmac.New(sha512.New512_256, []byte(secret)))
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

func Decrypt(text, secret string) (string, error) {

	//	Generate Key from Secret using HMAC
	key, err := hash.Hash([]byte(secret), hmac.New(sha512.New512_256, []byte(secret)))
	if err != nil {
		return "", err
	}

	//	Generate Decipher Block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := library.DecodeBase64(text)
	if err != nil {
		return "", err
	}

	//	Extract Nonce
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	//	Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil

}
