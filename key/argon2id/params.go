package argon2id

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shresht7/gocrypt/utils"
	"golang.org/x/crypto/argon2"
)

//	Input parameters for the argon2id key-derivation function
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

//	Sensible defaults for the argon2id key-derivation function
var DefaultParams Params = Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

//	Encode the parameters along with the salt and key
func (p *Params) Encode(salt, derivedKey []byte) []byte {
	return []byte(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%x$%x", argon2.Version, p.Memory, p.Iterations, p.Parallelism, salt, derivedKey))
}

//	Extracts the argon2id parameters, salt and derived key from the given hash.
//	It returns an error if the hash format is invalid and/or the parameters are invalid
func Decode(hash []byte) (Params, []byte, []byte, error) {

	s := strings.Split(string(hash), "$")

	if len(s) != 6 {
		return Params{}, nil, nil, ErrInvalidHash
	}

	if version, err := strconv.Atoi(s[2]); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var params Params
	var err error

	_, err = fmt.Scanf(s[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	salt, err := utils.DecodeHex(s[4])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.SaltLength = uint32(len(salt))

	derivedKey, err := utils.DecodeHex(s[5])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.KeyLength = uint32(len(derivedKey))

	//	TODO: Check

	return params, salt, derivedKey, nil

}
