package argon2id

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shresht7/gocrypt/library"
	"golang.org/x/crypto/argon2"
)

//	Input parameters for the argon2id key-derivation function
type Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

//	Sensible defaults for the argon2id key-derivation function
var DefaultParams Params = Params{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

//	Encode the parameters along with the salt and key
func (p *Params) Encode(salt, derivedKey []byte) []byte {
	return []byte(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%x$%x", argon2.Version, p.memory, p.iterations, p.parallelism, salt, derivedKey))
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

	_, err = fmt.Scanf(s[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	salt, err := library.DecodeHex(s[4])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.saltLength = uint32(len(salt))

	derivedKey, err := library.DecodeHex(s[5])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.keyLength = uint32(len(derivedKey))

	//	TODO: Check

	return params, salt, derivedKey, nil

}
