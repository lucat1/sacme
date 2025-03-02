package sacme

import (
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/pelletier/go-toml/v2"
)

type RawAccount struct {
	Email     string  `toml:"email"`
	KeyType   KeyType `toml:"key_type"`
	AcceptTOS bool    `toml:"accept_tos"`
	Directroy *string `toml:"directory"`
}

type Account struct {
	Email     string
	KeyType   KeyType
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

	if len(acc.Email) <= 0 {
		err = fmt.Errorf("%w: domain definition lacks email", MissingEmail)
		return
	}

	acc.KeyType = DEFAULT_KEY_TYPE
	if len(raw.KeyType) > 0 {
		acc.KeyType = raw.KeyType
	}
	if !VALID_KEY_TYPES[acc.KeyType] {
		err = fmt.Errorf("invalid key type: %s", acc.KeyType)
		return
	}

	dir := DEFAULT_DIRECTORY
	if raw.Directroy != nil {
		dir = *raw.Directroy
	}
	acc.Directroy, err = url.Parse(dir)
	if err != nil {
		err = fmt.Errorf("could not parse ACME directory URL: %w", err)
		return
	}

	a = &acc
	return
}

type Authentication struct {
	Method  AuthenticationMethod `json:"method"`
	Options map[string]string    `json:"options"`
}

// ValidateAuthentication validates authentication parameters and sets
// defaults values for the authentication section of a domain definition.
func ValidateAuthentication(raw Authentication) (a *Authentication, err error) {
	var auth Authentication

	auth.Method = DEFAULT_AUTHENTICATION_METHOD
	if len(raw.Method) > 0 {
		auth.Method = raw.Method
	}
	if !VALID_AUTHENTICATION_METHODS[auth.Method] {
		err = fmt.Errorf("invalid authentication method: %s", auth.Method)
		return
	}

	auth.Options = DEFAULT_AUTHENTICATION_OPTIONS[auth.Method]
	for key, val := range raw.Options {
		if !VALID_AUTHENTICATION_OPTIONS[auth.Method][key] {
			err = fmt.Errorf("unexpected option %s for method %s", key, auth.Method)
			return
		}

		auth.Options[key] = val
	}

	a = &auth
	return
}

type RawPathPerm struct {
	Path string `toml:"path"`
	// TODO: rename from perm to mode
	Perm  string `toml:"perm"`
	Owner string `toml:"owner"`
	Group string `toml:"group"`
}

type PathPerm struct {
	Path  string
	Perm  os.FileMode
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
		err = fmt.Errorf("could not convert install path to absolute: %w", err)
		return
	}
	pp, err := strconv.ParseInt(raw.Perm, 0, 0)
	if err != nil {
		err = fmt.Errorf("could not parse permission value (should start with 0): %w", err)
		return
	}
	perm.Perm = os.FileMode(pp)
	perm.Owner, err = user.Lookup(raw.Owner)
	if err != nil {
		err = fmt.Errorf("could not find owner user for install: %w", err)
		return
	}
	perm.Group, err = user.LookupGroup(raw.Group)
	if err != nil {
		err = fmt.Errorf("could not find group for install: %w", err)
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
			err = fmt.Errorf("invalid install definition for `key`: %w", err)
			return
		}
	}

	if raw.Crt != nil {
		inst.Crt, err = ValidatePathPerm(*raw.Crt)
		if err != nil {
			err = fmt.Errorf("invalid install definition for `crt`: %w", err)
			return
		}
	}

	if raw.CA != nil {
		inst.CA, err = ValidatePathPerm(*raw.CA)
		if err != nil {
			err = fmt.Errorf("invalid install definition for `ca`: %w", err)
			return
		}
	}

	if raw.Concat != nil {
		inst.Concat, err = ValidatePathPerm(*raw.Concat)
		if err != nil {
			err = fmt.Errorf("invalid install definition for `concat`: %w", err)
			return
		}
	}

	i = &inst
	return
}

type RawDomain struct {
	Domain         string         `toml:"domain"`
	Account        RawAccount     `toml:"account"`
	Authentication Authentication `toml:"authentication"`
	Installs       []RawInstall   `toml:"installs"`
}

type Domain struct {
	Domain         string
	Account        Account
	Authentication Authentication
	Installs       []Install
}

// PraseDomain parses a RawDomain into an Domain struct by parsing all
// RawPathPerm structs
func ValidateDomain(raw RawDomain) (d *Domain, err error) {
	dom := Domain{
		Domain: raw.Domain,
	}
	if len(dom.Domain) <= 0 {
		err = fmt.Errorf("missing domain record: %w", err)
		return
	}

	var acc *Account
	acc, err = ValidateAccount(raw.Account)
	if err != nil {
		err = fmt.Errorf("could not validate account definition: %w", err)
		return
	}
	dom.Account = *acc

	var auth *Authentication
	auth, err = ValidateAuthentication(raw.Authentication)
	if err != nil {
		err = fmt.Errorf("could not validate authentication definition: %w", err)
		return
	}
	dom.Authentication = *auth

	for i, rawInst := range raw.Installs {
		var inst *Install
		inst, err = ValidateInstall(rawInst)
		if err != nil {
			err = fmt.Errorf("could not validate install definition at position %d: %w", i, err)
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
		err = fmt.Errorf("could not parse domain TOML definition: %w", err)
		return
	}

	d, err = ValidateDomain(domain)
	if err != nil {
		err = fmt.Errorf("could not verify domain definition: %w", err)
		return
	}

	return
}
