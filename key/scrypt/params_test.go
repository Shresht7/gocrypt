package scrypt

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Shresht7/gocrypt/utils"
)

//	Helper function to generate params, salt and derived key
func GenerateParamsSaltAndKey() (Params, []byte, []byte, error) {

	//	Initialize parameters
	params := DefaultParams

	//	Generate Salt
	salt, err := utils.GenerateBytes(int(params.SaltLength))
	if err != nil {
		return params, nil, nil, err
	}

	//	Generate Key
	derivedKey, err := utils.GenerateBytes(int(params.KeyLength))
	if err != nil {
		return params, nil, nil, err
	}

	return params, salt, derivedKey, nil

}

//	Test Params Check
func TestParamsCheck(t *testing.T) {

	//	Initialize Params
	params := DefaultParams

	//	Check the params
	if err := params.Check(); err != nil {
		t.Error("params are invalid")
	}

	//	Invalid N
	params.N = 0
	if err := params.Check(); err == nil {
		t.Error("N must be greater than zero")
	}
	params.N = 3
	if err := params.Check(); err == nil {
		t.Error("N must be a power of two")
	}

	//	Invalid R
	params.R = 0
	if err := params.Check(); err == nil {
		t.Error("R must be greater than zero")
	}

	//	Invalid P
	params.P = 0
	if err := params.Check(); err == nil {
		t.Error("P must be greater than zero")
	}

	//	Invalid Salt Length
	params.SaltLength = minSaltLength - 1
	if err := params.Check(); err == nil {
		t.Errorf("Salt length must be at least %d", minSaltLength)
	}

	//	Invalid Key Length
	params.KeyLength = minKeyLength - 1
	if err := params.Check(); err == nil {
		t.Errorf("Key length must be at least %d", minKeyLength)
	}

}

//	Test Params Encode
func TestParamsEncode(t *testing.T) {

	//	Initialize Params, Salt and Key
	params, salt, derivedKey, err := GenerateParamsSaltAndKey()
	if err != nil {
		t.Error(err)
	}

	//	Encode the params, salt and the derived key
	str := string(params.Encode(salt, derivedKey))

	//	Split the string into parts using the delimiter '$'
	s := strings.Split(str, "$")

	//  The length of the encoded string must be 5
	if len(s) != 5 {
		t.Errorf("The length of the encoded string must be 5 got %d", len(s))
	}

	//	str should match the format: N$r$p$salt$derivedKey
	if s[0] != fmt.Sprintf("%d", params.N) {
		t.Errorf("N must be %d", params.N)
	}
	if s[1] != fmt.Sprintf("%d", params.R) {
		t.Errorf("R must be %d", params.R)
	}
	if s[2] != fmt.Sprintf("%d", params.P) {
		t.Errorf("P must be %d", params.P)
	}
	if s[3] != utils.EncodeHex(salt) {
		t.Errorf("salt must be %x", salt)
	}
	if s[4] != utils.EncodeHex(derivedKey) {
		t.Errorf("derived key must be %x", derivedKey)
	}

}

//	Test Params Decode
func TestParamsDecode(t *testing.T) {

	//	Generate Params, Salt and Key
	params, salt, derivedKey, err := GenerateParamsSaltAndKey()
	if err != nil {
		t.Error(err)
	}

	//	Encode the params, salt and the derived key
	hash := params.Encode(salt, derivedKey)

	//	Decode the hash and retrieve params, salt and derived key
	params2, salt2, derivedKey2, err := Decode(hash)
	if err != nil {
		t.Error(err)
	}

	//	Compare the params
	if params != params2 {
		t.Errorf("params must be %v", params)
	}

	//	Compare the salt
	if !bytes.Equal(salt, salt2) {
		t.Errorf("salt must be %x", salt)
	}

	//	Compare the derived key
	if !bytes.Equal(derivedKey, derivedKey2) {
		t.Errorf("derivedKey must be %x", derivedKey)
	}

	//	Invalid hash
	hash = []byte("invalid")
	_, _, _, err = Decode(hash)
	if err == nil {
		t.Error("hash was invalid")
	}

	//	Invalid params
	hash = []byte("8$1$1$16$16$32")
	_, _, _, err = Decode(hash)
	if err == nil {
		t.Error("params were invalid")
	}

	//	Invalid salt length
	hash = []byte("8$1$1$16$16$32")
	_, _, _, err = Decode(hash)
	if err == nil {
		t.Error("salt length was invalid")
	}

	//	Invalid key length
	hash = []byte("8$1$1$16$32$32")
	_, _, _, err = Decode(hash)
	if err == nil {
		t.Error("key length was invalid")
	}

}

var params, salt, derivedKey, _ = GenerateParamsSaltAndKey()

//	Benchmark Encode
func BenchmarkEncode(b *testing.B) {
	//	Encode the params, salt and the derived key
	for i := 0; i < b.N; i++ {
		params.Encode(salt, derivedKey)
	}
}

var hash = params.Encode(salt, derivedKey)

//	Benchmark Decode
func BenchmarkDecode(b *testing.B) {
	//	Encode the params, salt and the derived key
	for i := 0; i < b.N; i++ {
		Decode(hash)
	}
}
