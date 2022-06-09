//	Provides symmetric authenticated encryption using XChaCha20-Poly1305 AEAD
package xchacha20poly1305

import (
	"github.com/Shresht7/gocrypt/hash"
	"github.com/Shresht7/gocrypt/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

//	Generates a new key from the given secret of the given size using argon2id.
//	Panics if the key generation fails.
func GenerateKey(secret []byte) []byte {
	key, err := hash.HMAC_SHA_512_256(secret, string(secret))
	if err != nil {
		panic(err) //	Key generation is critical
	}
	return key
}

//	Encrypt the given text
func Encrypt(text, secret []byte) ([]byte, error) {

	//	Generate Key from argon2id
	key := GenerateKey(secret)

	//	Generate Cipher Block
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext := []byte(text)

	//	Generate Nonce
	nonce, err := utils.GenerateBytes(aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if err != nil {
		return nil, err
	}

	//	Seal the text
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

//	Decrypt the given ciphertext
func Decrypt(text, secret []byte) ([]byte, error) {

	//	Generate Key from argon2id
	key := GenerateKey(secret)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := []byte(text)

	//	Split ciphertext into nonce and ciphertext
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	if err != nil {
		return nil, err
	}

	//	Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
