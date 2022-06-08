package bcrypt

import "golang.org/x/crypto/bcrypt"

const WORK_FACTOR = 14

//	Hashes the password using bcrypt
func HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, WORK_FACTOR)
}

//	Verify the password with the given hash. Returns error on failure.
func VerifyPassword(password, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
