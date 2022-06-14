package stream

import (
	"bytes"
	"os"
	"testing"
)

const (
	original string = "../sample/original.md"
	lock     string = "../sample/original.md.lock"
	new      string = "../sample/new.md"
)

func TestEncryptDecrypt(t *testing.T) {

	var err error

	originalText, err := os.ReadFile(original)
	if err != nil {
		t.Error(err)
	}

	err = EncryptFile(original, lock, "seven", "seven")
	if err != nil {
		t.Error(err)
	}

	lockText, err := os.ReadFile(lock)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(originalText, lockText) {
		t.Error("Encrypted text matches original text")
	}

	err = DecryptFile(lock, new, "seven", "seven")
	if err != nil {
		t.Error(err)
	}

	newText, err := os.ReadFile(new)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(originalText, newText) {
		t.Error("Decrypted text does not match original text")
	}

}
