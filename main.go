package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/Shresht7/gocrypt/library"
)

const TEXT = "Hello Go"
const SECRET = "C104K3D!C104K3D!"

func main() {
	rand.Seed(time.Now().UnixNano())

	encryptedText, err := Encrypt(TEXT, SECRET)
	library.Check(err)

	fmt.Println(encryptedText)
}
