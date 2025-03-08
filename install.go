package sacme

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"

	fs "github.com/spf13/afero"
)

func (pp1 PathPermState) Matches(pp2 PathPerm) bool {
	return pp1 == pp2.State()
}

func (i1 InstallState) Matches(i2 Install) bool {
	result := true
	if i1.Key != nil {
		result = result && i2.Key != nil && i1.Key.Matches(*i2.Key)
	}

	if i1.Crt != nil {
		result = result && i2.Crt != nil && i1.Crt.Matches(*i2.Crt)
	}

	if i1.CA != nil {
		result = result && i2.CA != nil && i1.CA.Matches(*i2.CA)
	}

	if i1.Concat != nil {
		result = result && i2.Concat != nil && i1.Concat.Matches(*i2.Concat)
	}

	return result
}

func (pp1 PathPerm) Matches(pp2 PathPermState) bool {
	return pp1.State() == pp2
}

func (i1 Install) Matches(i2 InstallState) bool {
	result := true
	if i1.Key != nil {
		result = result && i2.Key != nil && i1.Key.Matches(*i2.Key)
	}

	if i1.Crt != nil {
		result = result && i2.Crt != nil && i1.Crt.Matches(*i2.Crt)
	}

	if i1.CA != nil {
		result = result && i2.CA != nil && i1.CA.Matches(*i2.CA)
	}

	if i1.Concat != nil {
		result = result && i2.Concat != nil && i1.Concat.Matches(*i2.Concat)
	}

	return result
}

func writeFile(f fs.Fs, pp PathPerm, content []byte, installType string) (err error) {
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

func removeFile(f fs.Fs, path string) (err error) {
	err = f.Remove(path)
	if err != nil {
		err = fmt.Errorf("could not remove file %s: %w", path, err)
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

func (i Install) Install(f fs.Fs, state *State) (isp *InstallState, err error) {
	var is InstallState

	if i.Key != nil {
		if err = writeFile(f, *i.Key, state.ACME.PrivateKey, "key"); err != nil {
			return
		}
		ks := (*i.Key).State()
		is.Key = &ks
	}

	if i.Crt != nil {
		if err = writeFile(f, *i.Crt, state.ACME.Certificate, "crt"); err != nil {
			return
		}
		ks := (*i.Crt).State()
		is.Crt = &ks
	}

	if i.CA != nil {
		if err = writeFile(f, *i.CA, state.ACME.IssuerCertificate, "ca"); err != nil {
			return
		}
		ks := (*i.CA).State()
		is.CA = &ks
	}

	if i.Concat != nil {
		concat := []byte{}
		concat = append(concat, state.ACME.PrivateKey[:]...)
		concat = append(concat, state.ACME.Certificate[:]...)

		if err = writeFile(f, *i.Concat, concat, "concat"); err != nil {
			return
		}
		ks := (*i.Concat).State()
		is.Concat = &ks
	}

	isp = &is
	return
}

func (i *InstallState) Uninstall(f fs.Fs) (err error) {
	if i.Key != nil {
		if err = removeFile(f, i.Key.Path); err != nil {
			return
		}
	}

	if i.Crt != nil {
		if err = removeFile(f, i.Crt.Path); err != nil {
			return
		}
	}

	if i.CA != nil {
		if err = removeFile(f, i.CA.Path); err != nil {
			return
		}
	}

	if i.Concat != nil {
		if err = removeFile(f, i.Concat.Path); err != nil {
			return
		}
	}

	return
}
