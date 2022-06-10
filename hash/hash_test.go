package hash

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

var data = []byte("salt and pepper")
var newData = []byte("mac and cheese")

//	Test the Hash function
func TestHash(t *testing.T) {

	//	Test the Hash function
	hash1, err := Hash(data, sha256.New())
	if err != nil {
		t.Error(err)
	}

	//	Hash should be different from the data
	if bytes.Equal(data, hash1) {
		t.Error("Hash: data is the same as the hash")
	}

	hash2, err := Hash(data, sha256.New())
	if err != nil {
		t.Error(err)
	}

	//	Hashes should be deterministic
	if !bytes.Equal(hash1, hash2) {
		t.Error("Hash: hashes are not deterministic")
	}

	//	Length of the hash should be the same for any data
	if len(hash1) != len(hash2) {
		t.Error("Hash: hashes are not the same length")
	}

}

//	Test SHA256
func TestSHA256(t *testing.T) {

	hash1, err := SHA256(data)
	if err != nil {
		t.Error(err)
	}

	//	same data should produce the same hashes
	hash2, err := SHA256(data)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(hash1, hash2) {
		t.Error("SHA256: same data do not produce the same hash")
	}

	//	should produce a 32-bit hash
	if len(hash1) != 32 {
		t.Error("SHA256: hash is not 32-bits")
	}

	hash3, err := SHA256(newData)
	if err != nil {
		t.Error(err)
	}

	//	Length of the hash should be the same for any data
	if len(hash1) != len(hash3) {
		t.Error("SHA256: hashes are not the same length")
	}

}

//	Test SHA512
func TestSHA512(t *testing.T) {

	hash1, err := SHA512(data)
	if err != nil {
		t.Error(err)
	}

	//	same data should produce the same hashes
	hash2, err := SHA512(data)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(hash1, hash2) {
		t.Error("SHA512: same data do not produce the same hash")
	}

	//	should produce a 64-bit hash
	if len(hash1) != 64 {
		t.Error("SHA512: hash is not 64-bits")
	}

	hash3, err := SHA512(newData)
	if err != nil {
		t.Error(err)
	}

	//	Length of the hash should be the same for any data
	if len(hash1) != len(hash3) {
		t.Error("SHA512: hashes are not the same length")
	}

}

//	Test HMAC-SHA-512/256
func TestHMAC_SHA_512_256(t *testing.T) {

	hash1, err := HMAC_SHA_512_256(data, "tagged")
	if err != nil {
		t.Error(err)
	}

	//	same tags should produce the same hashes
	hash2, err := HMAC_SHA_512_256(data, "tagged")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(hash1, hash2) {
		t.Error("HMAC_SHA_512_256: same tags do not produce the same hash")
	}

	//	different tags should produce different hashes
	hash3, err := HMAC_SHA_512_256(data, "different tag")
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(hash1, hash3) {
		t.Error("HMAC_SHA_512_256: different tags produce the same hash")
	}

	//	different data should produce different hashes
	hash4, err := HMAC_SHA_512_256(newData, "tagged")
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(hash1, hash4) {
		t.Error("HMAC_SHA_512_256: different data produce the same hash")
	}

	//	should produce a 32-bit hash
	if len(hash1) != 32 {
		t.Error("HMAC_SHA_512_256: hash is not 32-bits")
	}

	//	length of the hash should be the same for any data
	if len(hash1) != len(hash4) {
		t.Error("HMAC_SHA_512_256: hashes are not the same length")
	}
}
