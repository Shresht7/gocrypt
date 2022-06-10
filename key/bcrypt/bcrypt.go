package bcrypt

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

//	Higher than bcrypt default cost
const DEFAULT_COST = 14

//	Hashes the password using bcrypt
func Hash(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}

//	Verify the password with the given hash. Returns error on failure
func Verify(password, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}

//	Returns the hashing cost for the given hash. When, in the future,
//	the hashing cost of a password system needs to be increased to adjust for
//	greater computational power, this function allows one to establish which passwords need to be updated.
func Cost(hash []byte) (int, error) {
	return bcrypt.Cost(hash)
}

//	Upgrade the password using the new cost. Returns an error if the password and hash do not match,
//	or the new cost is lower than the current cost.
func Upgrade(password, hash []byte, newCost int) ([]byte, error) {

	//	Verify that the password and hash match
	if err := Verify(password, hash); err != nil {
		return nil, err
	}

	//	Determine the cost
	cost, err := Cost(hash)
	if err != nil {
		return nil, err
	}
	if newCost < cost {
		return nil, errors.New("new cost is lower than the current cost")
	}

	//	Upgrade the password
	return Hash(password, newCost)
}
