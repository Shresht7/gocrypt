package argon2id

import (
	"crypto/subtle"

	"github.com/Shresht7/gocrypt/library"
	"golang.org/x/crypto/argon2"
)

func Hash(password []byte, params Params) ([]byte, error) {

	//	TODO: Check Params

	//	Generate Salt
	salt, err := library.GenerateBytes(int(params.saltLength))
	if err != nil {
		panic(err)
	}

	//	Derive the key
	derivedKey := argon2.IDKey(password, salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	result := params.Encode(salt, derivedKey)
	return result, nil
}

func Verify(password, hash []byte) error {

	//	Decode the hash and retrieve argon2id parameters and the salt
	params, salt, derivedKey, err := Decode(hash)
	if err != nil {
		return err
	}

	//	argon2id the plaintext using the given salt and parameters
	target := argon2.IDKey(password, salt, params.iterations, params.memory, params.parallelism, params.keyLength)
	if err != nil {
		return err
	}

	//	Constant-Time Compare
	if subtle.ConstantTimeCompare(derivedKey, target) == 1 {
		return nil
	}

	return ErrMismatchHashAndPassword

}
