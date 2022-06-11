package argon2id

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

//	Test Params Encode
func TestParamsEncode(t *testing.T) {

	//	Initialize Params, Salt and Derived Key
	params, salt, derivedKey, err := GenerateParamsSaltAndKey()
	if err != nil {
		t.Error(err)
	}

	//	Encode the params and salt and the derived key
	str := string(params.Encode(salt, derivedKey))

	// Split the string into parts using the delimiter "$"
	parts := strings.Split(str, "$")

	//	The length of the encoded string must be 6
	if len(parts) != 6 {
		t.Errorf("The length of the encoded string must be 6")
	}

	//	The encoded string should have the following format: "$argon2id$v=19$m=65536,t=1,p=1$salt$derivedKey"
	if parts[2] != fmt.Sprintf("v=%d", params.Version) {
		t.Errorf("Version must be %d", params.Version)
	}
	if parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", params.Memory, params.Iterations, params.Parallelism) {
		t.Errorf("Memory must be %d", params.Memory)
	}
	if parts[4] != utils.EncodeHex(salt) {
		t.Errorf("salt must be %x", salt)
	}
	if parts[5] != utils.EncodeHex(derivedKey) {
		t.Errorf("derived key must be %x", derivedKey)
	}

}

//	Test Params Decode
func TestParamsDecode(t *testing.T) {

	//	Generate Params, Salt and Derived Key
	params, salt, derivedKey, err := GenerateParamsSaltAndKey()
	if err != nil {
		t.Error(err)
	}

	//	Encode the params and salt and the derived key
	hash := params.Encode(salt, derivedKey)

	//	Decode the hash and retrieve argon2id parameters, salt and derived key
	params2, salt2, derivedKey2, err := Decode(hash)
	if err != nil {
		t.Error(err)
	}

	//	Compare the parameters
	if params != params2 {
		t.Errorf("params must be %v", params)
	}

	//	Compare the salt
	if !bytes.Equal(salt, salt2) {
		t.Errorf("salt must be %x", salt)
	}

	//	Compare the derived key
	if !bytes.Equal(derivedKey, derivedKey2) {
		t.Errorf("derived key must be %x", derivedKey)
	}

	//	Invalid hash
	hash = []byte("invalid")
	_, _, _, err = Decode(hash)
	if err == nil {
		t.Error("hash was invalid")
	}

	//	Invalid params
	hash = []byte("$argon2id$v=19$m=65536,t=1,p=1$0$0")
	_, _, _, err = Decode(hash)
	if err == nil {
		t.Error("params were invalid")
	}

}

//	Initialize Params, Salt and Derived Key
var params, salt, derivedKey, _ = GenerateParamsSaltAndKey()

//	Benchmark Params Encode
func BenchmarkParamsEncode(b *testing.B) {
	//	Encode the params and salt and the derived key
	for i := 0; i < b.N; i++ {
		params.Encode(salt, derivedKey)
	}
}

var hash = params.Encode(salt, derivedKey)

//	Benchmark Params Decode
func BenchmarkParamsDecode(b *testing.B) {
	//	Encode the params and salt and the derived key
	for i := 0; i < b.N; i++ {
		Decode(hash)
	}
}
