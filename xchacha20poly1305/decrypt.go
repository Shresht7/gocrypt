package xchacha20poly1305

import (
	"github.com/Shresht7/gocrypt/key/argon2id"
	"golang.org/x/crypto/chacha20poly1305"
)

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
