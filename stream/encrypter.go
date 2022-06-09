package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
)

//	================
//  STREAM ENCRYPTER
//	================

//	Stream Encrypter is an encrypter for a stream of data with authentication
type StreamEncrypter struct {
	Source io.Reader
	Block  cipher.Block
	Stream cipher.Stream
	MAC    hash.Hash
	IV     []byte
}

//	Creates a new Stream Encrypter
func NewStreamEncrypter(key, macKey []byte, plainText io.Reader) (*StreamEncrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, macKey)

	return &StreamEncrypter{
		Source: plainText,
		Block:  block,
		Stream: stream,
		MAC:    mac,
		IV:     iv,
	}, nil
}

//	Encrypts the bytes of the Source reader and and places them into p
func (s *StreamEncrypter) Read(p []byte) (int, error) {
	n, readErr := s.Source.Read(p)
	if n > 0 {
		s.Stream.XORKeyStream(p[:n], p[:n])
		err := writeHash(s.MAC, p[:n])
		if err != nil {
			return n, err
		}
		return n, readErr
	}
	return 0, io.EOF
}
