package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
)

//	================
//  STREAM DECRYPTER
//	================

//	Stream Decrypter is a decrypter for a stream of data with authentication
type StreamDecrypter struct {
	Source io.Reader
	Block  cipher.Block
	Stream cipher.Stream
	MAC    hash.Hash
	Meta   StreamMeta
}

//	Creates a new StreamDecrypter
func NewStreamDecrypter(key, macKey []byte, meta StreamMeta, cipherText io.Reader) (*StreamDecrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, meta.IV)
	mac := hmac.New(sha256.New, macKey)

	return &StreamDecrypter{
		Source: cipherText,
		Block:  block,
		Stream: stream,
		MAC:    mac,
		Meta:   meta,
	}, nil
}

//	Reads the byte from the reader and decrypts them
func (s *StreamDecrypter) Read(p []byte) (int, error) {
	n, readErr := s.Source.Read(p)
	if n > 0 {
		err := writeHash(s.MAC, p[:n])
		if err != nil {
			return n, err
		}
		s.Stream.XORKeyStream(p[:n], p[:n])
		return n, readErr
	}
	return 0, io.EOF
}

//	Verifies that the hash of the stream is correct. This should only be called after the processing is finished
func (s *StreamDecrypter) Authenticate() error {
	if hmac.Equal(s.Meta.Hash, s.MAC.Sum(nil)) {
		return errors.New("authentication failed")
	}
	return nil
}

//	================
//  HELPER FUNCTIONS
//	================

//	Write MAC Hash
func writeHash(MAC hash.Hash, p []byte) error {
	m, err := MAC.Write(p)
	if err != nil {
		return err
	}

	if m != len(p) {
		return errors.New("could not write all bytes to HMAC")
	}
	return nil
}
