package main

import (
	"fmt"
)

const TEXT = "Hello Go"
const SECRET = "C104K3D!C104K3D!"

func main() {
	encryptedText, err := Encrypt(TEXT, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println(encryptedText)

	decryptedText, err := Decrypt(encryptedText, SECRET)
	if err != nil {
		panic(err)
	}

	fmt.Println(decryptedText)
}
