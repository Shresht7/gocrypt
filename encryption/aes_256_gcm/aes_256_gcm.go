//	Provides symmetric authenticated encryption using AES-GCM-256 AEAD
package aes_256_gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/Shresht7/gocrypt/hash"
	"github.com/Shresht7/gocrypt/utils"
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

//	Encrypt the given plaintext using the given secret using AES-GCM-256.
//	Output: nonce||ciphertext|tag where | is concatenation
func Encrypt(plaintext, secret []byte) ([]byte, error) {

	//	Generate key from secret
	key := GenerateKey(secret)

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
	nonce, err := utils.GenerateBytesWithCapacity(gcm.NonceSize(), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
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
	key := GenerateKey(secret)

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
