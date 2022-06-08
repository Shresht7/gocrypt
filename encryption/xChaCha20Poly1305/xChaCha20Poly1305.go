//	Provides symmetric authenticated encryption using XChaCha20-Poly1305 AEAD
package xchacha20poly1305

import (
	"github.com/Shresht7/gocrypt/key/argon2id"
	"github.com/Shresht7/gocrypt/library"
	"golang.org/x/crypto/chacha20poly1305"
)

//	Encrypt the given text
func Encrypt(text, secret string) (string, error) {

	//	Generate Key from argon2id
	key, err := argon2id.Hash([]byte(secret), argon2id.DefaultParams)
	if err != nil {
		return "", err
	}

	//	Generate Cipher Block
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)

	//	Generate Nonce
	nonce, err := library.GenerateBytesWithCapacity(aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if err != nil {
		return "", err
	}

	//	Seal the text
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	return library.EncodeBase64(ciphertext), nil
}

func Decrypt(text, secret string) (string, error) {

	//	Generate Key from argon2id
	key, err := argon2id.Hash([]byte(secret), argon2id.DefaultParams)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	ciphertext := []byte(text)

	//	Split ciphertext into nonce and ciphertext
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	if err != nil {
		return "", err
	}

	//	Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
