package utils

import "testing"

//	Test Generate Bytes
func TestGenerateBytes(t *testing.T) {
	//	Generate a byte slice of capacity 10
	b, err := GenerateBytes(10)
	if err != nil {
		t.Errorf("Error generating bytes: %v", err)
	}

	//	Check that the string is of capacity 10
	if cap(b) != 10 {
		t.Errorf("Bytes is not of capacity 10: %v", b)
	}

	//	Generate a byte slice of length 10
	b, err = GenerateBytesWithCapacity(10, 10)
	if err != nil {
		t.Errorf("Error generating bytes: %v", err)
	}

	//	Check that the string is of length 10
	if cap(b) != 10 {
		t.Errorf("Bytes is not of length 10: %v", b)
	}

}
