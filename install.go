package sacme

import (
	"bytes"
	"io"
	"os"

	fs "github.com/warpfork/go-fsx"
)

func writeFile(f fs.FS, pp PathPerm, content []byte, installType string) (err error) {
	handle, err := fs.OpenFile(f, pp.Path, os.O_CREATE|os.O_WRONLY, fs.FileMode(pp.Perm))
	if err != nil {
		err = InstallFile.Wrap(err, "could not open file %s for writing %s", pp.Path, installType)
		return
	}

	defer handle.Close()

	l, err := io.Copy(handle.(io.Writer), bytes.NewReader(content))
	if err != nil {
		err = WriteToFile.Wrap(err, "error while writing %d bytes to file %s", len(content), pp.Path)
		return
	}

	if int(l) != len(content) {
		err = UnfinishedWrite.New("wrote %d bytes, expected to write %d", l, len(content))
		return
	}

	return
}

func (pp PathPerm) State() PathPermState {
	return PathPermState{
		Path:  pp.Path,
		Perm:  uint32(pp.Perm),
		Owner: pp.Owner.Uid,
		Group: pp.Group.Gid,
	}
}

func (s *State) Install(f fs.FS, i Install) (isp *InstallState, err error) {
	var is InstallState

	if i.Key != nil {
		if err = writeFile(f, *i.Key, s.ACME.PrivateKey, "key"); err != nil {
			return
		}
		ks := (*i.Key).State()
		is.Key = &ks
	}

	isp = &is
	return
}
