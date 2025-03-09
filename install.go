package sacme

import (
	"github.com/lucat1/sacme/pkg/file"
	fs "github.com/spf13/afero"
)

func (i1 InstallState) Matches(i2 Install) bool {
	result := true
	if i1.Key != nil {
		result = result && i2.Key != nil && *i1.Key == pathPermToState(i2.Key)
	}

	if i1.Crt != nil {
		result = result && i2.Crt != nil && *i1.Crt == pathPermToState(i2.Crt)
	}

	if i1.CA != nil {
		result = result && i2.CA != nil && *i1.CA == pathPermToState(i2.CA)
	}

	if i1.Concat != nil {
		result = result && i2.Concat != nil && *i1.Concat == pathPermToState(i2.Concat)
	}

	return result
}

func (i1 Install) Matches(i2 InstallState) bool {
	result := true
	if i1.Key != nil {
		result = result && i2.Key != nil && pathPermToState(i1.Key) == *i2.Key
	}

	if i1.Crt != nil {
		result = result && i2.Crt != nil && pathPermToState(i1.Crt) == *i2.Crt
	}

	if i1.CA != nil {
		result = result && i2.CA != nil && pathPermToState(i1.CA) == *i2.CA
	}

	if i1.Concat != nil {
		result = result && i2.Concat != nil && pathPermToState(i1.Concat) == *i2.Concat
	}

	return result
}

func pathPermToState(pp *file.PathPerm) PathPermState {
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
		if err = file.WriteFile(f, *i.Key, state.ACME.PrivateKey, "key"); err != nil {
			return
		}
		ks := pathPermToState(i.Key)
		is.Key = &ks
	}

	if i.Crt != nil {
		if err = file.WriteFile(f, *i.Crt, state.ACME.Certificate, "crt"); err != nil {
			return
		}
		ks := pathPermToState(i.Crt)
		is.Crt = &ks
	}

	if i.CA != nil {
		if err = file.WriteFile(f, *i.CA, state.ACME.IssuerCertificate, "ca"); err != nil {
			return
		}
		ks := pathPermToState(i.CA)
		is.CA = &ks
	}

	if i.Concat != nil {
		concat := []byte{}
		concat = append(concat, state.ACME.PrivateKey[:]...)
		concat = append(concat, state.ACME.Certificate[:]...)

		if err = file.WriteFile(f, *i.Concat, concat, "concat"); err != nil {
			return
		}
		ks := pathPermToState(i.Concat)
		is.Concat = &ks
	}

	isp = &is
	return
}

func (i *InstallState) Uninstall(f fs.Fs) (err error) {
	if i.Key != nil {
		if err = file.RemoveFile(f, i.Key.Path); err != nil {
			return
		}
	}

	if i.Crt != nil {
		if err = file.RemoveFile(f, i.Crt.Path); err != nil {
			return
		}
	}

	if i.CA != nil {
		if err = file.RemoveFile(f, i.CA.Path); err != nil {
			return
		}
	}

	if i.Concat != nil {
		if err = file.RemoveFile(f, i.Concat.Path); err != nil {
			return
		}
	}

	return
}
