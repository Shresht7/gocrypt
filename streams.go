package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
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

//	===============
//	STREAM METADATA
//	===============

//	Metadata about the encrypted stream
type StreamMeta struct {
	//	Initialization Vector for the cryptographic function
	IV []byte
	//	HMAC hash of the stream
	Hash []byte
}

//	Returns the encrypted streams metadata for use in decrypting. This should be called after the stream is finished
func (s *StreamEncrypter) Meta() StreamMeta {
	return StreamMeta{IV: s.IV, Hash: s.MAC.Sum(nil)}
}

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

//	=====================
//	FILE STREAM ENCRYPTER
//	=====================

func EncryptFile(src, dst, key, macKey string) error {

	keyHash := sha256.Sum256([]byte(key))
	macHash := sha256.Sum256([]byte(macKey))

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	encrypter, err := NewStreamEncrypter(keyHash[:], macHash[:], srcFile)
	if err != nil {
		return err
	}

	io.Copy(dstFile, encrypter)

	metadata := encrypter.Meta()

	fmt.Println(metadata.IV, "\t", metadata.Hash)

	metadataBytes := make([]byte, len(metadata.IV)+len(metadata.Hash))
	metadataBytes = append(metadata.Hash, metadataBytes...)
	metadataBytes = append(metadata.IV, metadataBytes...)
	err = os.WriteFile(dst, metadataBytes, 0777)
	if err != nil {
		return err
	}

	return nil
}

func DecryptFile(src, dst, key, macKey string) error {

	keyHash := sha256.Sum256([]byte(key))
	macHash := sha256.Sum256([]byte(macKey))

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	hashIV := make([]byte, 32+aes.BlockSize)
	_, err = srcFile.Read(hashIV)
	if err != nil {
		return nil
	}

	hash := hashIV[:32]
	iv := hashIV[32:]

	metadata := StreamMeta{IV: iv, Hash: hash}
	fmt.Println(metadata.IV, metadata.Hash)

	decrypter, err := NewStreamDecrypter(keyHash[:], macHash[:], metadata, srcFile)
	if err != nil {
		return nil
	}

	io.Copy(os.Stdout, decrypter)

	return nil
}
