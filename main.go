package main

import (
	"fmt"

	"github.com/Shresht7/gocrypt/encryption/aes_256_gcm"
	"github.com/Shresht7/gocrypt/stream"
)

var TEXT = []byte("Hello Go")
var SECRET = []byte("C104K3D!")

func main() {
	fmt.Println("PlainText:\t", TEXT)

	encryptedText, err := aes_256_gcm.Encrypt(TEXT, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println("CipherText:\t", encryptedText)

	decryptedText, err := aes_256_gcm.Decrypt(encryptedText, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Text:\t", decryptedText)

	stream.EncryptFile("README.md", "README.lock.md", "seven", "seven")

	stream.DecryptFile("README.lock.md", "test", "seven", "seven")
}
