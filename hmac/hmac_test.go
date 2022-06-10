package hmac

import (
	"testing"

	"github.com/Shresht7/gocrypt/hash"
)

var data = []byte("mach-IV")
var key, _ = hash.SHA256([]byte("secret"))

//	Test HMAC
func TestHMAC(t *testing.T) {

	hmac := Generate(data, key)

	//  should verify with the correct parameters
	if !Verify(data, hmac, key) {
		t.Error("HMAC: failed to verify")
	}

	//	should fail to verify with a different key
	if Verify(data, hmac, []byte("wrong")) {
		t.Error("HMAC: verified with wrong key")
	}

	//	should fail to verify with a different data
	if Verify([]byte("wrong"), hmac, key) {
		t.Error("HMAC: verified with wrong data")
	}

	//  Modify the data and verify it fails
	data[0] ^= 0xFF
	if Verify(data, hmac, key) {
		t.Error("HMAC: verified with modified data")
	}

}
