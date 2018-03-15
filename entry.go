package shad0w

import (
	"time"
	"fmt"
	"strconv"

	"crypto/rand"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
)

const (
	MD5      = 1
	BlowFish = 2 // TODO: implement this
	SHA256   = 5
	SHA512   = 6
)

type entry struct {
	User        string
	AlgoID      int
	Salt        []byte
	Hashed      []byte
	LastChanged time.Time
}

func newEntry(user, pass string, algo int) (ret entry, err error) {
	ret = entry{
		User: user,
	}

	if len(user)*len(pass) == 0 {
		err = fmt.Errorf("User and password cannot be empty")
		return
	}

	salt := make([]byte, 32)
	rand.Read(salt)

	ret.Salt = salt
	ret.AlgoID = algo

	switch algo {
	case MD5:
		arr := md5.Sum(append(ret.Salt, []byte(pass)...))
		ret.Hashed = arr[:]
	case SHA256:
		arr := sha256.Sum256(append(ret.Salt, []byte(pass)...))
		ret.Hashed = arr[:]
	case SHA512:
		arr := sha512.Sum512(append(ret.Salt, []byte(pass)...))
		ret.Hashed = arr[:]
	default:
		return ret, fmt.Errorf("hashing algorithm invalid")
	}

	ret.LastChanged = time.Now()

	return

}

func parseEntry(str string) (ret entry, err error) {
	// user:$id$salt$hash:lastChange
	fields := strings.Split(str, ":")
	if len(fields) != 3 {
		err = fmt.Errorf("improper file formatting")
		return
	}


	//$id$salt$hash
	pwfields := strings.Split(fields[1], "$")
	if len(pwfields) != 4 {
		err = fmt.Errorf("improper file formatting")
		return
	}

	//algo string to int
	algo, err := strconv.Atoi(pwfields[1])
	if err != nil {
		return
	}

	// salt and hash from base64 to raw bytes
	salt, err := fromBase64(pwfields[2])
	if err != nil {
		return
	}
	hashed, err := fromBase64(pwfields[3])
	if err != nil {
		return
	}


	// last change in unix time
	secs, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return
	}
	lastChange := time.Unix(secs, 0)

	return entry{
		User: fields[0],
		AlgoID: algo,
		Salt: salt,
		Hashed: hashed,
		LastChanged: lastChange,
	}, nil
}

func (e *entry) verify(pass string) bool {

	var test []byte

	switch e.AlgoID {
	case MD5:
		arr := md5.Sum(append(e.Salt, []byte(pass)...))
		test = arr[:]
	case SHA256:
		arr := sha256.Sum256(append(e.Salt, []byte(pass)...))
		test = arr[:]
	case SHA512:
		arr := sha512.Sum512(append(e.Salt, []byte(pass)...))
		test = arr[:]
	default:
		return false
	}

	if len(test) != len(e.Hashed) {
		return false
	}

	for i := range test {
		if test[i] != e.Hashed[i] {
			return false
		}
	}

	return true
}

// $id$salt$hashed
func (e *entry) PassString() string {
	return fmt.Sprintf("$%d$%s$%s", e.AlgoID, toBase64(e.Salt), toBase64(e.Hashed))
}

func (e *entry) String() string {

	pass := e.PassString()
	lastChanged := strconv.FormatInt(e.LastChanged.Unix(), 10)

	return fmt.Sprintf("%s:%s:%s", e.User, pass, lastChanged)
}
