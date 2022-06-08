package argon2id

import "errors"

var ErrInvalidHash = errors.New("argon2id: invalid hash")

var ErrMismatchHashAndPassword = errors.New("argon2id: hash and password do not match")
