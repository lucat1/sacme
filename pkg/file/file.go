package file

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	fs "github.com/spf13/afero"
)

type PathPerm struct {
	Path  string
	Perm  os.FileMode
	Owner *user.User
	Group *user.Group
}

func WriteFile(f fs.Fs, pp PathPerm, content []byte, installType string) (err error) {
	handle, err := f.OpenFile(pp.Path, os.O_CREATE|os.O_WRONLY, os.FileMode(pp.Perm))
	if err != nil {
		err = fmt.Errorf("could not open file %s for writing %s: %w", pp.Path, installType, err)
		return
	}

	defer handle.Close()

	l, err := io.Copy(handle.(io.Writer), bytes.NewReader(content))
	if err != nil {
		err = fmt.Errorf("error while writing %d bytes to file %s: %w", len(content), pp.Path, err)
		return
	}

	if int(l) != len(content) {
		err = fmt.Errorf("wrote %d bytes, expected to write %d", l, len(content))
		return
	}

	uid, err := strconv.Atoi(pp.Owner.Uid)
	if err != nil {
		err = fmt.Errorf("could not parse uid %s (user %s) as int: %w", pp.Owner.Uid, pp.Owner.Username, err)
		return
	}
	gid, err := strconv.Atoi(pp.Group.Gid)
	if err != nil {
		err = fmt.Errorf("could not parse gid %s (group %s) as int: %w", pp.Group.Gid, pp.Group.Name, err)
		return
	}
	if err = f.Chown(pp.Path, uid, gid); err != nil {
		err = fmt.Errorf("could not chown %s to %s(%d):%s(%d): %w", pp.Path, pp.Owner.Username, uid, pp.Group.Name, gid, err)
		return
	}

	return
}

func RemoveFile(f fs.Fs, path string) (err error) {
	err = f.Remove(path)
	if err != nil {
		err = fmt.Errorf("could not remove file %s: %w", path, err)
		return
	}

	return
}
