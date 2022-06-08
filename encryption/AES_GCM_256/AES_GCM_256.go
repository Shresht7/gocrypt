//	Provides symmetric authenticated encryption using AES-GCM-256 AEAD
package aes_gcm_256

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/Shresht7/gocrypt/key/argon2id"
	"github.com/Shresht7/gocrypt/library"
)

//	Generates a new key from the given secret of the given size using argon2id.
//	Panics if the key generation fails.
func GenerateKey(secret []byte, size uint32) []byte {
	params := argon2id.DefaultParams
	params.KeyLength = size //	Adjust the key length

	key, err := argon2id.Hash(secret, params)
	if err != nil {
		panic(err) //	Panic if key generation fails
	}
	return key
}

//	Encrypt the given plaintext using the given secret using AES-GCM-256.
//	Output: nonce||ciphertext|tag where | is concatenation
func Encrypt(plaintext, secret []byte) ([]byte, error) {

	//	Generate key from secret
	key := GenerateKey(secret, 32) //	16, 24, or 32 bytes to select AES-128, AES-192, or AES-256

	//	Generate cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//	Wrap block cipher in GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//	Generate nonce
	nonce, err := library.GenerateBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	//	Seal the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil

}

//	Decrypt the given ciphertext using the given secret using AES-GCM-256.
//	Input: nonce||ciphertext|tag where | is concatenation
func Decrypt(ciphertext, secret []byte) ([]byte, error) {

	//	Generate key from secret
	key := GenerateKey(secret, 32) //	16, 24, or 32 bytes to select AES-128, AES-192, or AES-256

	//	Generate decipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//	Wrap block cipher in GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//	Check ciphertext length against GCM nonce size
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrMalformedCiphertext
	}

	//	Extract nonce from ciphertext
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	//	Decrypt ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil

}

//	Errors
var (
	ErrMalformedCiphertext = errors.New("malformed ciphertext")
)
