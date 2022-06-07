package main

import (
	"crypto/sha256"
)

func Hash(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	byteSlice := h.Sum(nil)
	return byteSlice
}
