package bcrypt

import "testing"

//	Test bcrypt Hash and Verify
func TestBcrypt(t *testing.T) {

	//	Hash the password
	hash, err := Hash([]byte("password"), DEFAULT_COST)
	if err != nil {
		t.Error(err)
	}

	//	Verify the password
	if err := Verify([]byte("password"), hash); err != nil {
		t.Error(err)
	}

	//	Should not verify with the wrong password
	if err := Verify([]byte("wrong"), hash); err == nil {
		t.Error("Bcrypt: verified with wrong password")
	}

}

//	Test bcrypt Cost
func TestBcryptCost(t *testing.T) {

	//	Hash the password
	hash, err := Hash([]byte("password"), DEFAULT_COST)
	if err != nil {
		t.Error(err)
	}

	//  Check that the cost is default cost
	cost, err := Cost(hash)
	if err != nil {
		t.Error(err)
	}

	if cost != DEFAULT_COST {
		t.Errorf("Bcrypt: cost %d -- expected %d", cost, DEFAULT_COST)
	}
}

//	Test bcrypt upgrade
func TestBcryptUpgrade(t *testing.T) {

	//	Hash the password
	hash, err := Hash([]byte("password"), DEFAULT_COST)
	if err != nil {
		t.Error(err)
	}

	//	Upgrade the password
	newCost := DEFAULT_COST + 1
	hash, err = Upgrade([]byte("password"), hash, newCost)
	if err != nil {
		t.Error(err)
	}

	//	Verify the password
	if err := Verify([]byte("password"), hash); err != nil {
		t.Error(err)
	}

	//	Check that the cost has now upgraded
	cost, err := Cost(hash)
	if err != nil {
		t.Error(err)
	}

	if cost != newCost {
		t.Errorf("Bcrypt: cost %d -- expected: %d", cost, newCost)
	}

}

//	Benchmark bcrypt hashing
func BenchmarkBcryptHash(b *testing.B) {

	//	Hash the password
	for i := 0; i < b.N; i++ {
		_, err := Hash([]byte("password"), DEFAULT_COST)
		if err != nil {
			b.Error(err)
		}
	}

}

var hash, _ = Hash([]byte("password"), DEFAULT_COST) //	Generate hash outside benchmarks

//	Benchmark bcrypt verification
func BenchmarkBcryptVerify(b *testing.B) {

	//	Verify the password
	for i := 0; i < b.N; i++ {
		if err := Verify([]byte("password"), hash); err != nil {
			b.Error(err)
		}
	}

}

//	Benchmark bcrypt cost
func BenchmarkBcryptCost(b *testing.B) {

	//	Check that the cost is default cost
	for i := 0; i < b.N; i++ {
		_, err := Cost(hash)
		if err != nil {
			b.Error(err)
		}
	}

}

//	Benchmark bcrypt upgrade
func BenchmarkBcryptUpgrade(b *testing.B) {

	//	Upgrade the password
	newCost := DEFAULT_COST + 1
	for i := 0; i < b.N; i++ {
		_, err := Upgrade([]byte("password"), hash, newCost)
		if err != nil {
			b.Error(err)
		}
	}

}
