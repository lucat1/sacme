package sacme

import (
	"net/url"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/pelletier/go-toml"
)

type RawAccount struct {
	Email     string  `toml:"email"`
	AcceptTOS bool    `toml:"accept_tos"`
	Directroy *string `toml:"directory"`
}

type Account struct {
	Email     string
	AcceptTOS bool
	// desipite the type this field is always available
	Directroy *url.URL
}

// ValidateAccount parses a RawAccount into an Account struct, resolving the URL
// for the ACME directory or using the default value for it.
func ValidateAccount(raw RawAccount) (a *Account, err error) {
	acc := Account{
		Email:     raw.Email,
		AcceptTOS: raw.AcceptTOS,
	}

	dir := DEFAULT_DIRECTORY
	if raw.Directroy != nil {
		dir = *raw.Directroy
	}
	acc.Directroy, err = url.Parse(dir)
	if err != nil {
		err = InvalidDirectory.Wrap(err, "could not parse ACME directory URL")
		return
	}

	a = &acc
	return
}

type RawPathPerm struct {
	Path  string `toml:"path"`
	Perm  string `toml:"perm"`
	Owner string `toml:"owner"`
	Group string `toml:"group"`
}

type PathPerm struct {
	Path  string
	Perm  int64
	Owner *user.User
	Group *user.Group
}

// PrasePathPerm parses a RawPathPerm into an PathPerm struct, resolving the
// install path to absolute, as well as querying the getent system for
// user/group data.
func ValidatePathPerm(raw RawPathPerm) (p *PathPerm, err error) {
	var perm PathPerm

	perm.Path, err = filepath.Abs(raw.Path)
	if err != nil {
		err = InvalidPath.Wrap(err, "could not convert install path to absolute")
		return
	}
	perm.Perm, err = strconv.ParseInt(raw.Perm, 0, 0)
	if err != nil {
		err = InvalidPerm.Wrap(err, "could not parse permission value (should start with 0)")
		return
	}
	perm.Owner, err = user.Lookup(raw.Owner)
	if err != nil {
		err = InvalidOwner.Wrap(err, "could not find owner user for install")
		return
	}
	perm.Group, err = user.LookupGroup(raw.Group)
	if err != nil {
		err = InvalidGroup.Wrap(err, "could not find group for install")
		return
	}

	p = &perm
	return
}

type RawInstall struct {
	Key    *RawPathPerm `json:"key"`
	Crt    *RawPathPerm `json:"crt"`
	CA     *RawPathPerm `json:"ca"`
	Concat *RawPathPerm `json:"concat"`
}

type Install struct {
	Key    *PathPerm
	Crt    *PathPerm
	CA     *PathPerm
	Concat *PathPerm
}

// PraseInstall parses a RawInstall into an Install struct by validating all
// RawPathPerm structs
func ValidateInstall(raw RawInstall) (i *Install, err error) {
	var inst Install

	if raw.Key != nil {
		inst.Key, err = ValidatePathPerm(*raw.Key)
		if err != nil {
			err = InvalidInstall.Wrap(err, "invalid install definition for `key`")
			return
		}
	}

	if raw.Crt != nil {
		inst.Crt, err = ValidatePathPerm(*raw.Crt)
		if err != nil {
			err = InvalidInstall.Wrap(err, "invalid install definition for `crt`")
			return
		}
	}

	if raw.CA != nil {
		inst.CA, err = ValidatePathPerm(*raw.CA)
		if err != nil {
			err = InvalidInstall.Wrap(err, "invalid install definition for `ca`")
			return
		}
	}

	if raw.Concat != nil {
		inst.Concat, err = ValidatePathPerm(*raw.Concat)
		if err != nil {
			err = InvalidInstall.Wrap(err, "invalid install definition for `concat`")
			return
		}
	}

	i = &inst
	return
}

type RawDomain struct {
	Domains  []string     `toml:"domains"`
	Account  RawAccount   `toml:"account"`
	Installs []RawInstall `toml:"installs"`
}

type Domain struct {
	Domains  []string
	Account  Account
	Installs []Install
}

// PraseDomain parses a RawDomain into an Domain struct by parsing all
// RawPathPerm structs
func ValidateDomain(raw RawDomain) (d *Domain, err error) {
	dom := Domain{
		Domains: raw.Domains,
	}

	var acc *Account
	acc, err = ValidateAccount(raw.Account)
	if err != nil {
		err = InvalidAccount.Wrap(err, "could not verify account definition")
		return
	}
	dom.Account = *acc

	for i, rawInst := range raw.Installs {
		var inst *Install
		inst, err = ValidateInstall(rawInst)
		if err != nil {
			err = InvalidInstall.Wrap(err, "could not verify install definition at position %d", i)
			return
		}
		dom.Installs = append(dom.Installs, *inst)
	}

	d = &dom
	return
}

func ParseDomain(data []byte) (d *Domain, err error) {
	var domain RawDomain
	err = toml.Unmarshal(data, &domain)
	if err != nil {
		err = InvalidRawDomain.Wrap(err, "could not parse domain TOML definition")
		return
	}

	d, err = ValidateDomain(domain)
	if err != nil {
		err = InvalidDomain.Wrap(err, "could not verify domain definition")
		return
	}

	return
}
