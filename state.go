package sacme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"os"

	fs "github.com/warpfork/go-fsx"

	"github.com/go-acme/lego/v4/certcrypto"
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

func (state ACMEState) Empty() bool {
	return len(state.Certificate) <= 0
}

func (state ACMEState) Certificates() (certs []*x509.Certificate, err error) {
	if state.Empty() {
		err = MissingCertificate.New("requested certificate list for an ACME state which is missing certificates")
		return
	}
	certs, err = certcrypto.ParsePEMBundle(state.Certificate)
	if err != nil {
		err = ParseCertificates.Wrap(err, "could not parse certificate bundle as x509")
		return
	}

	return
}

// State holds the account/acme/installation state for a domain
type State struct {
	Account AccountState
	ACME    ACMEState
}

func (s *State) IsRegistered() bool {
	return s.Account.Registration != nil
}

type StateStore struct {
	fs fs.FS
}

func NewStateStore(f fs.FS) StateStore {
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
		err = GenerateKey.Wrap(err, "unable to generate account key")
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
			err = NewStateError.Wrap(err, "could not initialize a new state for domain %s", domain.Domain)
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
		err = DecodeState.Wrap(err, "invalid state content")
		return
	}

	s = &state
	return
}

func (ss StateStore) Store(domain Domain, state *State) (err error) {
	handle, err := fs.OpenFile(ss.fs, domain.Domain, os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		err = OpenStoreFile.Wrap(err, "could not open state file for writing for domain %s", domain.Domain)
		return
	}

	defer handle.Close()
	decoder := json.NewEncoder(handle.(io.Writer))
	err = decoder.Encode(state)
	if err != nil {
		err = EncodeState.Wrap(err, "invalid state content")
		return
	}

	return
}
