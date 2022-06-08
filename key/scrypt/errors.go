package scrypt

import "errors"

var ErrInvalidParams = errors.New("scrypt parameters are invalid")

var ErrInvalidHash = errors.New("invalid scrypt hash format")

var ErrMismatchHashAndPassword = errors.New("password and scrypt hash do not match")
