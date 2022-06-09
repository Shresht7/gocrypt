package stream

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"
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
