package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Shresht7/gocrypt/encryption/aes_256_gcm"
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

	file, _ := os.Open("README.md")
	dest, _ := os.Create("README.md.enc")
	encrypter, _ := NewStreamEncrypter([]byte(SECRET), []byte(SECRET), file)
	io.Copy(dest, encrypter)

	meta := encrypter.Meta()

	newFile, _ := os.Open("README.md.enc")

	decrypter, _ := NewStreamDecrypter([]byte(SECRET), []byte(SECRET), meta, newFile)
	io.Copy(os.Stdout, decrypter)
}
