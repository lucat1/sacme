package sacme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"golang.org/x/exp/slog"
	"io"
	"math/big"
	"os"

	fs "github.com/spf13/afero"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
)

type PrivateKey struct {
	key *ecdsa.PrivateKey
}

var curve = elliptic.P256()

func NewPrivateKey() (pk *PrivateKey, err error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return
	}
	pk = &PrivateKey{key: key}
	return
}

type RawPrivateKey struct {
	D *big.Int
	X *big.Int
	Y *big.Int
}

func (pk PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(RawPrivateKey{
		D: pk.key.D,
		X: pk.key.X,
		Y: pk.key.Y,
	})
}

func (a *PrivateKey) UnmarshalJSON(data []byte) error {
	var rpk RawPrivateKey
	if err := json.Unmarshal(data, &rpk); err != nil {
		return err
	}

	a.key = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     rpk.X,
			Y:     rpk.Y,
		},
		D: rpk.D,
	}
	return nil
}

type AccountState struct {
	Email        string
	Registration *registration.Resource
	Key          *PrivateKey
}

// Implement registration.User
func (a *AccountState) GetEmail() string {
	return a.Email
}
func (a AccountState) GetRegistration() *registration.Resource {
	return a.Registration
}
func (a *AccountState) GetPrivateKey() crypto.PrivateKey {
	if a.Key != nil {
		return a.Key.key
	}
	return nil
}

type ACMEState struct {
	Domain        string
	CertURL       string
	CertStableURL string

	PrivateKey        []byte
	Certificate       []byte
	IssuerCertificate []byte
	CSR               []byte
}

func (state ACMEState) ToResource() certificate.Resource {
	return certificate.Resource{
		Domain:            state.Domain,
		CertURL:           state.CertURL,
		CertStableURL:     state.CertStableURL,
		PrivateKey:        state.PrivateKey,
		Certificate:       state.Certificate,
		IssuerCertificate: state.IssuerCertificate,
		CSR:               state.CSR,
	}
}

func NewACMEState(res *certificate.Resource) ACMEState {
	return ACMEState{
		Domain:            res.Domain,
		CertURL:           res.CertURL,
		CertStableURL:     res.CertStableURL,
		PrivateKey:        res.PrivateKey,
		Certificate:       res.Certificate,
		IssuerCertificate: res.IssuerCertificate,
		CSR:               res.CSR,
	}
}

func (state ACMEState) Empty() bool {
	return len(state.Certificate) <= 0
}

func (state ACMEState) Certificates() (certs []*x509.Certificate, err error) {
	if state.Empty() {
		err = fmt.Errorf("%w: requested certificate list for an ACME state which is missing certificates", MissingCertificate)
		return
	}
	certs, err = certcrypto.ParsePEMBundle(state.Certificate)
	if err != nil {
		err = fmt.Errorf("could not parse certificate bundle as x509: %w", err)
		return
	}

	return
}

type PathPermState struct {
	Path string
	Perm uint32
	// the ID of the owner
	Owner string
	// the ID of the group
	Group string
}

func (p1 PathPermState) Equals(p2 PathPermState) bool {
	fmt.Println("checking for equality!")
	return false
}

type InstallState struct {
	Key    *PathPermState
	Crt    *PathPermState
	CA     *PathPermState
	Concat *PathPermState
}

// State holds the account/acme/installation state for a domain
type State struct {
	Account  AccountState
	ACME     ACMEState
	Installs []InstallState
}

func (s *State) IsRegistered() bool {
	return s.Account.Registration != nil
}

type StateStore struct {
	fs fs.Fs
}

func NewStateStore(f fs.Fs) StateStore {
	return StateStore{fs: f}
}

func NewState(domain Domain) (s *State, err error) {
	state := State{
		Account: AccountState{
			Email: domain.Account.Email,
		},
	}

	state.Account.Key, err = NewPrivateKey()
	if err != nil {
		err = fmt.Errorf("unable to generate account key: %w", err)
		return
	}

	s = &state
	return
}

func (ss StateStore) Load(domain Domain) (s *State, err error) {
	handle, err := ss.fs.Open(domain.Domain)
	if err != nil {
		slog.Warn("could not load domain state", "domain", domain.Domain, "err", err)

		// Initialize a new state for the domain
		var e error
		s, e = NewState(domain)
		if e != nil {
			err = fmt.Errorf("could not initialize a new state for domain %s: %w", domain.Domain, err)
			return
		}

		err = nil
		return
	}

	defer handle.Close()
	var state State
	decoder := json.NewDecoder(handle)
	err = decoder.Decode(&state)
	if err != nil {
		err = fmt.Errorf("invalid state content: %w", err)
		return
	}

	s = &state
	return
}

func (ss StateStore) Store(domain Domain, state *State) (err error) {
	handle, err := ss.fs.OpenFile(domain.Domain, os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		err = fmt.Errorf("could not open state file for writing for domain %s: %w", domain.Domain, err)
		return
	}

	defer handle.Close()
	encoder := json.NewEncoder(handle.(io.Writer))
	err = encoder.Encode(state)
	if err != nil {
		err = fmt.Errorf("invalid state content: %w", err)
		return
	}

	return
}
