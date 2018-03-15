package shad0w

import (
	"os"
	"path"
	"fmt"
	"bufio"
)

const (
	DefaultAlgo = SHA256
)


type File struct {
	path string
	//file *os.File
	entries map[string]entry
}

func NewFile(p string) (*File, error) {
	_, err := os.OpenFile(p, os.O_RDWR | os.O_CREATE | os.O_EXCL, 0700)
	if err != nil {
		return nil, err
	}

	return &File{
		path: path.Dir(p),
		//file: file,
		entries: map[string]entry{},
	}, nil
}

func OpenFile(p string) (*File, error) {
	file, err := os.OpenFile(p, os.O_RDWR, 0700)
	if err != nil {
		return nil, err
	}

	entries := map[string]entry{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		ent, err := parseEntry(scanner.Text())
		if err != nil {
			return nil, err
		}
		entries[ent.User] = ent
	}

	return &File {
		path: p,
		entries: entries,
	}, nil
}

func (f *File) NewUser(name , pass string, algo int) (err error){
	entry, err := newEntry(name, pass, algo)
	if err != nil {
		return err
	}

	_, ok := f.entries[name]
	if ok {
		return fmt.Errorf("entry already used")
	}

	f.entries[name] = entry

	return nil
}

func (f *File) UserExists(user string) bool {
	_, ok := f.entries[user]
	return ok
}

func (f * File) Verify(name, pass string) bool {
	e, ok := f.entries[name]
	if !ok {
		return ok
	}

	return e.verify(pass)
}

func (f *File) Flush() error {
	fd, err := os.OpenFile(f.path, os.O_WRONLY | os.O_TRUNC, 0700)
	if err != nil {
		return err
	}

	for _, v := range f.entries {
		fmt.Fprintln(fd, v.String())
	}

	return fd.Close()
}