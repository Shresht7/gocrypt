package main

import (
	"fmt"
)

const TEXT = "Hello Go"
const SECRET = "C104K3D!"

func main() {

	fmt.Println("PlainText:\t", TEXT)

	encryptedText, err := Encrypt(TEXT, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println("CipherText:\t", encryptedText)

	decryptedText, err := Decrypt(encryptedText, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Text:\t", decryptedText)
}
