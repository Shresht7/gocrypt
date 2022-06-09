package aes_256_gcm

import "testing"

var (
	text   []byte = []byte("Symmetric authenticated encryption using AES-GCM-256 AEAD")
	secret []byte = []byte("404NotFound")
)

//	Tests the key generation
func TestGenerateKey(t *testing.T) {

	key := GenerateKey(secret)
	if len(key) != 32 {
		t.Error("key length should be 32")
	}

}

//	Test the encrypt / decrypt process
func TestEncryptDecrypt(t *testing.T) {

	ciphertext, err := Encrypt(text, secret)
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(ciphertext, secret)
	if err != nil {
		t.Error(err)
	}

	if string(text) != string(plaintext) {
		t.Error("plaintexts do not match")
	}

}

//	Test that decrypting a malformed ciphertext does not produce a plaintext
func TestMalformedCipherText(t *testing.T) {

	ciphertext, err := Encrypt(text, secret)
	if err != nil {
		t.Error(err)
	}

	//	Malform ciphertext
	ciphertext[0] ^= 0xff

	plaintext, err := Decrypt(ciphertext, secret)
	if err == nil {
		t.Error("decryption should have failed")
	}

	//	Plaintexts should not match
	if string(text) == string(plaintext) {
		t.Error("plaintexts should not match")
	}

}

//	Tests that different secrets produce different ciphertexts
func TestSecretCiphertext(t *testing.T) {

	ciphertext1, err := Encrypt(text, secret)
	if err != nil {
		t.Error(err)
	}

	ciphertext2, err := Encrypt(text, []byte("different secret"))
	if err != nil {
		t.Error(err)
	}

	if string(ciphertext1) == string(ciphertext2) {
		t.Error("ciphertexts should not match")
	}

}

//	Test that different plaintexts produce different ciphertexts
func TestPlaintextCiphertext(t *testing.T) {

	ciphertext1, err := Encrypt(text, secret)
	if err != nil {
		t.Error(err)
	}

	ciphertext2, err := Encrypt([]byte("different plaintext"), secret)
	if err != nil {
		t.Error(err)
	}

	if string(ciphertext1) == string(ciphertext2) {
		t.Error("ciphertexts should not match")
	}

}

//	Test that a different secret does not decrypt a ciphertext
func TestSecretDecrypt(t *testing.T) {

	ciphertext, err := Encrypt(text, secret)
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(ciphertext, []byte("different secret"))
	if err == nil {
		t.Error("decryption should have failed")
	}

	if string(text) == string(plaintext) {
		t.Error("plaintexts should not match")
	}

}
