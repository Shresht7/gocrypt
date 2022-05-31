package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/Shresht7/gocrypt/library"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	bytes := library.GenerateBytes(10)
	str := library.GenerateString(10)
	hex := library.GenerateHex(10)
	b64 := library.GenerateBase64(10)

	fmt.Println("Bytes:\t", bytes)
	fmt.Println("String:\t", str)
	fmt.Println("Hex:\t", hex)
	fmt.Println("Base64:\t", b64)
}
