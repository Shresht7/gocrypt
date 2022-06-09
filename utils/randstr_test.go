package utils

import (
	"strings"
	"testing"
)

//	Test the GenerateString function
func TestGenerateString(t *testing.T) {
	//	Generate a random string of length 10
	str, err := GenerateString(10)
	if err != nil {
		t.Errorf("Error generating string: %v", err)
	}

	//	Check that the string is of length 10
	if len(str) != 10 {
		t.Errorf("String is not of length 10: %v", str)
	}

	//	Generate a random string of length 10 using numbers
	str, err = GenerateString(10, NUMBERS)
	if err != nil {
		t.Errorf("Error generating string: %v", err)
	}

	//	Check that the string does not contain letters
	if strings.ContainsAny(str, ALPHABETS) {
		t.Errorf("String contains letters: %v", str)
	}

	//	Generate a random string of length 10 using lowercase alphabets
	str, err = GenerateString(10, LOWERCASE_ALPHABETS)
	if err != nil {
		t.Errorf("Error generating string: %v", err)
	}

	//	Check that the string does not contain numbers or uppercase alphabets
	if strings.ContainsAny(str, UPPERCASE_ALPHABETS) || strings.ContainsAny(str, NUMBERS) {
		t.Errorf("String contains uppercase alphabets: %v", str)
	}

	//	Generate a random string of length 10 using uppercase alphabets
	str, err = GenerateString(10, UPPERCASE_ALPHABETS)
	if err != nil {
		t.Errorf("Error generating string: %v", err)
	}

	//	Check that the string does not contain numbers or lowercase alphabets
	if strings.ContainsAny(str, LOWERCASE_ALPHABETS) || strings.ContainsAny(str, NUMBERS) {
		t.Errorf("String contains lowercase alphabets: %v", str)
	}

	//	Generate a random string of length 10 using custom character set
	str, err = GenerateString(10, "x")
	if err != nil {
		t.Errorf("Error generating string: %v", err)
	}

	//	Check that the string only contains the custom character set
	if !strings.ContainsAny(str, "x") {
		t.Errorf("String does not contain custom character set: %v", str)
	}
}
