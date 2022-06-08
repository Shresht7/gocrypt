package main

import (
	"fmt"

	"github.com/Shresht7/gocrypt/aes_gcm_256"
)

const TEXT = "Hello Go"
const SECRET = "C104K3D!"

func main() {

	fmt.Println("PlainText:\t", TEXT)

	encryptedText, err := aes_gcm_256.Encrypt(TEXT, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println("CipherText:\t", encryptedText)

	decryptedText, err := aes_gcm_256.Decrypt(encryptedText, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Text:\t", decryptedText)
}
