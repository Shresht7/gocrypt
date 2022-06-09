package scrypt

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Shresht7/gocrypt/utils"
	"golang.org/x/crypto/scrypt"
)

const (
	maxInt        = 1<<31 - 1 // Maximum Integer Value
	minSaltLength = 8         // Minimum Length of Salt
	minKeyLength  = 16        // Minimum Length of Derived Key
)

//	Input parameters for the scrypt key-derivation function
//	as described in Colin Percival's paper (http://www.tarsnap.com/scrypt/scrypt.pdf)
//	he recommended parameters for interactive logins as of 2017 are N=32768, r=8 and p=1.
//	The parameters N, r, and p should be increased as memory latency and CPU parallelism increases;
//	consider setting N to the highest power of 2 you can derive within 100 milliseconds.
type Params struct {
	n          int // CPU/Memory cost parameter (logN)
	r          int // Block size parameter (octets)
	p          int // Parallelization parameter (positive integer)
	saltLength int // Length of the salt (octets)
	keyLength  int // Length of the derived key (octets)
}

//	Sensible defaults for the scrypt key-derivation function
//	These defaults will consume 32MB of memory (128 * r * N)
//	The derived key will have a length of 32bytes (256bits)
var DefaultParams Params = Params{
	n:          32768,
	r:          8,
	p:          1,
	saltLength: 16,
	keyLength:  32,
}

//	Encode the parameters along with the salt and key
func (p *Params) Encode(salt, derivedKey []byte) []byte {
	return []byte(fmt.Sprintf("%d$%d$%d$%x$%x", p.n, p.r, p.p, salt, derivedKey))
}

//	Extracts the scrypt parameters, salt and derived key from the given hash.
//	It returns an error if the hash format is invalid and/or the parameters are invalid
func Decode(hash []byte) (Params, []byte, []byte, error) {

	s := strings.Split(string(hash), "$")

	//	N, r, p, salt, derivedKey
	if len(s) != 5 {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var params Params
	var err error

	params.n, err = strconv.Atoi(s[0])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	params.r, err = strconv.Atoi(s[1])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	params.p, err = strconv.Atoi(s[2])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	salt, err := utils.DecodeHex(s[3])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.saltLength = len(salt)

	derivedKey, err := utils.DecodeHex(s[4])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.keyLength = len(derivedKey)

	if err := params.Check(); err != nil {
		return params, nil, nil, err
	}

	return params, salt, derivedKey, nil

}

//	Check whether the input parameters are valid for the scrypt algorithm
func (p *Params) Check() error {

	//	Check N
	if p.n > maxInt || p.n <= 1 || p.n%2 != 0 {
		return ErrInvalidParams
	}

	//	Check r
	if p.r < 1 || p.r > maxInt {
		return ErrInvalidParams
	}

	//	Check p
	if p.p < 1 || p.p > maxInt {
		return ErrInvalidParams
	}

	//	Check that r and p do not exceed 2 ^ 30 and that N, r, p don't
	//	exceed the limits defined by the scrypt algorithm
	if uint64(p.r)*uint64(p.p) >= 1<<30 || p.r > maxInt/128/p.p || p.r > maxInt/256 || p.n > maxInt/128/p.r {
		return ErrInvalidParams
	}

	//	Check salt length
	if p.saltLength < minSaltLength || p.saltLength > maxInt {
		return ErrInvalidParams
	}

	//	Check derived key length
	if p.keyLength < minKeyLength || p.keyLength > maxInt {
		return ErrInvalidParams
	}

	//	Return nil if nothing bad happens
	return nil

}

//	Calibrates the parameters to be the hardest setting for the given time and memory constraints.
//	The params will use the given memory (MiB) and will take the given time to compute (but not less that timeout / 2)
//	The default timeout (when timeout == 0) is 200ms
//	The default memory usage (when memMiBytes = 0) is 32MiB
func (p *Params) Calibrate(timeout time.Duration, memMiBytes int) error {

	if err := p.Check(); err != nil {
		return err
	}

	if timeout == 0 {
		timeout = 200 * time.Millisecond
	}

	if memMiBytes == 0 {
		memMiBytes = 32
	}

	salt, err := utils.GenerateBytes(p.saltLength)
	if err != nil {
		return err
	}

	password := []byte("CalibrateThis")

	//	r is fixed to 8 and should not be used to tune the memory usage
	//	if the cache lines of future processors are bigger, then r should be increased
	// see: https://blog.filippo.io/the-scrypt-parameters/
	p.r = 8

	//	scrypt runs p independent mixing functions with a memory requirement of roughly
	//	128 * r * N. Depending on the implementation these can run sequentially or parallel.
	//	The go implementation runs the sequentially, therefore p can be used to adjust the execution time of the script
	//	We start with 1 and only increase if we have to
	p.p = 1

	// Memory usage is at least 128 * r * N, see
	// http://blog.ircmaxell.com/2014/03/why-i-dont-recommend-scrypt.html
	// or https://drupal.org/comment/4675994#comment-4675994
	//	Calculate N based on the desired memory usage
	memMiBytes = memMiBytes << 20
	p.n = 1
	for 128*int64(p.r)*int64(p.n) < int64(memMiBytes) {
		p.n <<= 1
	}
	p.n >>= 1

	//	Calculate the current execution time
	start := time.Now()
	if _, err := scrypt.Key(password, salt, p.n, p.r, p.p, p.keyLength); err != nil {
		return err
	}
	dur := time.Since(start)

	//	Try to reach desired timeout by increasing p
	//	The further away we are from the timeout, the bigger steps we should take
	for dur < timeout {
		//	the theoretical optimal p; can not be used because of inaccurate measuring
		optimalP := int(int64(timeout) / int64(dur) / int64(p.p))

		if optimalP > p.p+1 {
			//	use average between optimal p and current p
			p.p = (p.p + optimalP) / 2
		} else {
			p.p++
		}

		start = time.Now()
		if _, err := scrypt.Key(password, salt, p.n, p.r, p.p, p.keyLength); err != nil {
			return err
		}
		dur = time.Since(start)
	}

	//	lower by 1 to get shorter duration than timeout
	p.p--

	return p.Check()

}
