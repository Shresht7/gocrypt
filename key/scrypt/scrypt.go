package scrypt

import (
	"crypto/subtle"
	"time"

	"github.com/Shresht7/gocrypt/utils"
	"golang.org/x/crypto/scrypt"
)

//	Returns the derived key of the given password using the scrypt key-derivation functions
//	based on the given parameters. The parameters are prepended to the derived key and separated
//	by the "$" character (0x24). If the provided parameters are invalid, an error will be returned
func Hash(password []byte, params Params) ([]byte, error) {

	//	Check Params
	if err := params.Check(); err != nil {
		return nil, err
	}

	//	Generate Salt
	salt, err := utils.GenerateBytes(int(params.SaltLength))
	if err != nil {
		panic(err)
	}

	//	Derive the key
	derivedKey, err := scrypt.Key(password, salt, params.N, params.R, params.P, params.KeyLength)
	if err != nil {
		return nil, err
	}

	//	Prepend the params and the salt to the derived key, each separated
	//	by the "$" character (0x24). The salt and key are hex encoded
	result := params.Encode(salt, derivedKey)
	return result, nil
}

//	Compares a derived key with the potential password. The parameters from the derived key are used.
//	The comparison is constant-time. It returns nil on success and an error if derived keys do not match.
func Verify(password, hash []byte) error {

	//	Decode the hash and retrieve scrypt parameters and the salt
	params, salt, derivedKey, err := Decode(hash)
	if err != nil {
		return err
	}

	//	scrypt the plaintext using the given salt and parameters
	target, err := scrypt.Key(password, salt, params.N, params.R, params.P, params.KeyLength)
	if err != nil {
		return err
	}

	//	Constant-Time Compare
	if subtle.ConstantTimeCompare(derivedKey, target) == 1 {
		return nil
	}

	return ErrMismatchHashAndPassword

}

//	Upgrade the password-hash combination by recalibrating the scrypt parameters to the given timeout and memory constraints.
//	Returns an error if the password and hash do not match, calibration fails or rehash fails.
//	Returns a new hash with the updated parameters.
func Upgrade(password, hash []byte, timeout time.Duration, memMiBytes int) ([]byte, error) {

	//	Decode the hash and retrieve the salt and scrypt parameters
	params, _, _, err := Decode(hash)
	if err != nil {
		return nil, err
	}

	//	Verify the given password
	err = Verify(password, hash)
	if err != nil {
		return nil, err
	}

	//	Recalibrate parameters
	if err = params.Calibrate(timeout, memMiBytes); err != nil {
		return nil, err
	}

	//	Rehash password
	return Hash(password, params)

}
