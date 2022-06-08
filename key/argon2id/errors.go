package argon2id

import "errors"

var (
	ErrInvalidHash             = errors.New("invalid hash")
	ErrMismatchHashAndPassword = errors.New("hash and password do not match")
)
