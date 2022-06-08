package hash

import "hash"

//	Hash the data using the given Hash
func Hash(s []byte, h hash.Hash) ([]byte, error) {
	_, err := h.Write(s)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
