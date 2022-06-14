package argon2id

import (
	"crypto/subtle"

	"github.com/Shresht7/gocrypt/utils"
	"golang.org/x/crypto/argon2"
)

//	Returns the derived key of the given password using the argon2id key-derivation functions
//	based on the given parameters. The parameters are prepended to the derived key and separated
//	by the "$" character (0x24). If the provided parameters are invalid, an error will be returned
func Hash(password []byte, params Params) (result, salt, derivedKey []byte, err error) {

	//	TODO: Check Params

	//	Generate Salt
	salt, err = utils.GenerateBytes(int(params.SaltLength))
	if err != nil {
		panic(err)
	}

	//	Derive the key
	derivedKey = argon2.IDKey(password, salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	result = params.Encode(salt, derivedKey)

	return result, salt, derivedKey, nil
}

//	Compares a derived key with the potential password. The parameters from the derived key are used.
//	The comparison is constant-time. It returns nil on success and an error if derived keys do not match.
func Verify(password, hash []byte) error {

	//	Decode the hash and retrieve argon2id parameters and the salt
	params, salt, derivedKey, err := Decode(hash)
	if err != nil {
		return err
	}

	//	argon2id the plaintext using the given salt and parameters
	target := argon2.IDKey(password, salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	if err != nil {
		return err
	}

	//	Constant-Time Compare
	if subtle.ConstantTimeCompare(derivedKey, target) == 1 {
		return nil
	}

	return ErrMismatchHashAndPassword

}
