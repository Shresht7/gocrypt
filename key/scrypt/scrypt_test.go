package scrypt

import (
	"bytes"
	"testing"
	"time"
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
		t.Error("Scrypt: hash and password are the same")
	}

	//  hash should not be deterministic
	newHash, _, _, _ := Hash([]byte("password"), params)
	if bytes.Equal(hash, newHash) {
		t.Error("Scrypt: hash is deterministic")
	}

	//  hash should be different with different password
	wrongHash, _, _, _ := Hash([]byte("wrong"), params)
	if bytes.Equal(hash, wrongHash) {
		t.Error("Scrypt: hash is the same with different password")
	}

	//  hash should be different with different params
	newParams := DefaultParams
	newParams.KeyLength = 64
	diffHash, _, _, _ := Hash([]byte("password"), newParams)
	if bytes.Equal(hash, diffHash) {
		t.Error("Scrypt: hash is the same with different params")
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
	if err := Verify([]byte("password"), hash); err != nil {
		t.Error(err)
	}

	//	Should not verify with the wrong password
	if err := Verify([]byte("wrong"), hash); err == nil {
		t.Error("Scrypt: verified with wrong password")
	}

	//	Should not verify with the wrong hash
	if err := Verify([]byte("password"), []byte("wrong")); err == nil {
		t.Error("Scrypt: verified with wrong hash")
	}

}

func BenchmarkVerify(b *testing.B) {
	hash, _, _, _ := Hash([]byte("password"), DefaultParams)
	for i := 0; i < b.N; i++ {
		Verify([]byte("password"), hash)
	}
}

//	Test scrypt Upgrade
func TestScryptUpgrade(t *testing.T) {

	//	Initialize Params
	params := DefaultParams

	//	Hash the password
	hash, _, _, err := Hash([]byte("password"), params)
	if err != nil {
		t.Error(err)
	}

	//	Upgrade the password
	newHash, _, _, err := Upgrade([]byte("password"), hash, 250*time.Millisecond, 32)
	if err != nil {
		t.Error(err)
	}

	//	Verify the password
	if err := Verify([]byte("password"), newHash); err != nil {
		t.Error(err)
	}

	//	Should not verify with the wrong password
	if err := Verify([]byte("wrong"), newHash); err == nil {
		t.Error("Scrypt: verified with wrong password")
	}

}
