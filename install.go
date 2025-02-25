package sacme

import (
	"bytes"
	"errors"
	"io"
	"os"

	fs "github.com/warpfork/go-fsx"
)

func (pp1 PathPermState) Matches(pp2 PathPerm) bool {
	return pp1 == pp2.State()
}

func (i1 InstallState) Matches(i2 Install) bool {
	result := true
	result = result
	if i1.Key != nil {
		result = result && (i2.Key != nil || i1.Key.Matches(*i2.Key))
	}

	if i1.Crt != nil {
		result = result && (i2.Crt != nil || i1.Crt.Matches(*i2.Crt))
	}

	if i1.CA != nil {
		result = result && (i2.CA != nil || i1.CA.Matches(*i2.CA))
	}

	if i1.Concat != nil {
		result = result && (i2.Concat != nil || i1.Concat.Matches(*i2.Concat))
	}

	return result
}

func (pp1 PathPerm) Matches(pp2 PathPermState) bool {
	return pp1.State() == pp2
}

func (i1 Install) Matches(i2 InstallState) bool {
	result := true
	if i1.Key != nil {
		result = result && (i2.Key != nil && i1.Key.Matches(*i2.Key))
	}

	if i1.Crt != nil {
		result = result && (i2.Crt != nil && i1.Crt.Matches(*i2.Crt))
	}

	if i1.CA != nil {
		result = result && (i2.CA != nil && i1.CA.Matches(*i2.CA))
	}

	if i1.Concat != nil {
		result = result && (i2.Concat != nil && i1.Concat.Matches(*i2.Concat))
	}

	return result
}

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

func (i Install) Install(f fs.FS, state *State) (isp *InstallState, err error) {
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

func (i *InstallState) Uninstall(f fs.FS) (err error) {
	err = errors.New("TODO")
	return
}
