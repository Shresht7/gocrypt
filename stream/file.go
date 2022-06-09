package stream

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"io"
	"os"
)

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

	metadata := encrypter.Meta()

	composed := io.MultiReader(bytes.NewReader(metadata.IV), bytes.NewReader(metadata.Hash), encrypter)
	_, err = io.Copy(dstFile, composed)
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

	iv := hashIV[:aes.BlockSize]
	hash := hashIV[aes.BlockSize:]

	metadata := StreamMeta{IV: iv, Hash: hash}

	decrypter, err := NewStreamDecrypter(keyHash[:], macHash[:], metadata, srcFile)
	if err != nil {
		return nil
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	_, err = io.Copy(dstFile, decrypter)
	if err != nil {
		return err
	}

	return nil
}
