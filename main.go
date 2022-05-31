package main

import (
	"fmt"

	"github.com/Shresht7/gocrypt/library"
)

const TEXT = "Hello Go"
const SECRET = "C104K3D!C104K3D!"

func main() {
	encryptedText, err := Encrypt(TEXT, SECRET)
	library.Check(err)

	fmt.Println(encryptedText)

	decryptedText, err := Decrypt(encryptedText, SECRET)
	library.Check(err)

	fmt.Println(decryptedText)
}
