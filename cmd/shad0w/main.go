package main

import (
	"fmt"
	"flag"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/ear7h/shad0w"
	"log"
)

var fileName string
var newFile bool

var user string
var algo int
var verify bool
var verifyOnly bool

var help bool

func init() {
	flag.StringVar(&fileName, "file", "shadow", "file name")
	flag.BoolVar(&newFile, "n", false, "new file")

	flag.StringVar(&user, "u", "", "user")
	flag.IntVar(&algo, "algorithm", 5,
`Algorithm for newFile user
1: MD5
5: SHA-256
6: SHA-512
`)
	flag.BoolVar(&verify, "c", false, "check created user and password")
	flag.BoolVar(&verifyOnly, "C", false, "only check user and password")

	flag.BoolVar(&help, "h", false, "help")

	log.SetPrefix("")
}

func fatalf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
	os.Exit(0)
}

func main() {
	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	var file *shad0w.File
	var err error
	if newFile {
		file, err = shad0w.NewFile(fileName)
	} else {
		file, err = shad0w.OpenFile(fileName)
	}

	if err != nil {
		fatalf("error opening %s: %s\n", fileName, err.Error())
	}

	defer file.Flush()

	if !verifyOnly && user != "" {
		if file.UserExists(user) {
			fatalf("user %q exists\n", user)
		}

PassAgain:
		fmt.Println("enter a password")
		byt, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}
		pw := string(byt)

		fmt.Println("enter password again")
		byt, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}

		if pw != string(byt) {
			fmt.Println("passwords didn't match")
			goto PassAgain
		}

		err = file.NewUser(user, pw ,algo)
		if err != nil {
			panic(err)
		}

		file.Flush()
	}

	if (verify || verifyOnly) && user != "" {
		fmt.Printf("verifying %s\n", user)
		fmt.Println("enter password")
		byt, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fatalf("unexpected error: %v", err.Error())
		}

		ok := file.Verify(user, string(byt))
		if !ok {
			fatalf("password incorrect")
		}

		fmt.Println("password ok")
	}
}
