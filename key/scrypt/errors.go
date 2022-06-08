package scrypt

import "errors"

var (
	ErrInvalidParams           = errors.New("scrypt parameters are invalid")
	ErrInvalidHash             = errors.New("invalid scrypt hash format")
	ErrMismatchHashAndPassword = errors.New("password and scrypt hash do not match")
)
