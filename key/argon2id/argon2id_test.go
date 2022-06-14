package argon2id

import (
	"bytes"
	"testing"
)

//	Test Hash
func TestHash(t *testing.T) {

	//	Initialize Params
	params := DefaultParams

	//	Hash the password
	hash, _, _, err := Hash([]byte("password"), params)
	if err != nil {
		t.Error(err)
	}

	//  hash and password should not be the same
	if bytes.Equal(hash, []byte("password")) {
		t.Error("argon2id: hash and password are the same")
	}

	//  hash should not be deterministic
	newHash, _, _, _ := Hash([]byte("password"), params)
	if bytes.Equal(hash, newHash) {
		t.Error("argon2id: hash is deterministic")
	}

	//  hash should be different with different password
	wrongHash, _, _, _ := Hash([]byte("wrong"), params)
	if bytes.Equal(hash, wrongHash) {
		t.Error("argon2id: hash is the same with different password")
	}

	//  hash should be different with different params
	newParams := DefaultParams
	newParams.KeyLength = 64
	diffHash, _, _, _ := Hash([]byte("password"), newParams)
	if bytes.Equal(hash, diffHash) {
		t.Error("argon2id: hash is the same with different params")
	}

}

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Hash([]byte("password"), DefaultParams)
	}
}

//	Test Verify
func TestVerify(t *testing.T) {

	//	Initialize Params
	params := DefaultParams

	//	Hash the password
	hash, _, _, err := Hash([]byte("password"), params)
	if err != nil {
		t.Error(err)
	}

	//	Verify the password
	err = Verify([]byte("password"), hash)
	if err != nil {
		t.Error("argon2id: verify failed")
	}

}

func BenchmarkVerify(b *testing.B) {
	hash, _, _, _ := Hash([]byte("password"), DefaultParams)
	for i := 0; i < b.N; i++ {
		Verify([]byte("password"), hash)
	}
}
