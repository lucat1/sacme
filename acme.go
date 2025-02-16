package sacme

import (
	"fmt"
	"log/slog"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/go-retryablehttp"
)

func toKeyType(kt KeyType) certcrypto.KeyType {
	switch kt {
	case KEY_TYPE_P256:
		return certcrypto.EC256
	case KEY_TYPE_RSA2048:
		return certcrypto.RSA2048
	case KEY_TYPE_RSA4096:
		return certcrypto.RSA4096
	default:
		panic(fmt.Sprintf("invalid key type: %s", kt))
	}
}

func GetClient(domain Domain, state State) (client *lego.Client, err error) {
	config := lego.NewConfig(&state.Account)
	config.CADirURL = domain.Account.Directroy.String()
	config.Certificate.KeyType = toKeyType(domain.Account.KeyType)

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 5
	retryClient.HTTPClient = config.HTTPClient
	retryClient.Logger = slog.Default()
	config.HTTPClient = retryClient.StandardClient()

	client, err = lego.NewClient(config)
	if err != nil {
		err = CreateClient.Wrap(err, "could not create lego ACME client")
		return
	}

	return
}

func RegisterAccount(domain Domain, state *State) (err error) {
	if state.Account.Registration != nil {
		err = AccountAlreadyRegistered.New("account for domain %s already exists", domain.Domain)
		return
	}

	client, err := GetClient(domain, *state)
	if err != nil {
		return
	}

	state.Account.Registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: domain.Account.AcceptTOS})
	if err != nil {
		err = AccountRegistration.Wrap(err, "error while registering ACME client with the CA")
		return
	}

	return
}

func SetupProvider(domain Domain, client *lego.Client) (err error) {
	opts := domain.Authentication.Options
	switch domain.Authentication.Method {
	case AUTHENTICATION_METHOD_HTTP01_STANDALONE:
		iface := opts[AUTHENTICATION_OPTION_INTERFACE]
		port := opts[AUTHENTICATION_OPTION_PORT]
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(iface, port))
		if err != nil {
			err = ProviderHTTP01Standalone.Wrap(err, "could not setup handler for challange %s", domain.Authentication.Method)
			return
		}
	default:
		panic(fmt.Sprintf("invalid authentication method: %s", domain.Authentication.Method))
	}
	return
}

func ObtainCertificate(domain Domain, state *State) (err error) {
	client, err := GetClient(domain, *state)
	if err != nil {
		return
	}

	err = SetupProvider(domain, client)
	if err != nil {
		err = ProviderSetup.Wrap(err, "could not setup provider for ACME challange")
		return
	}

	certificate, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{domain.Domain},
		// TODO: do we want to bundle? I think this depends on the install type
		Bundle: true,
	})
	if err != nil {
		err = CertificateObtain.Wrap(err, "could not obtain certifiate through ACME")
		return
	}
	state.ACME = ACMEState{
		Domain:        certificate.Domain,
		CertURL:       certificate.CertURL,
		CertStableURL: certificate.CertStableURL,

		PrivateKey:        certificate.PrivateKey,
		Certificate:       certificate.Certificate,
		IssuerCertificate: certificate.IssuerCertificate,
		CSR:               certificate.CSR,
	}

	return
}

func RenewCertificate(domain Domain, state *State) (err error) {
	client, err := GetClient(domain, *state)
	if err != nil {
		return
	}

	err = SetupProvider(domain, client)
	if err != nil {
		err = ProviderSetup.Wrap(err, "could not setup provider for ACME challange")
		return
	}

	// TODO: renew
	// state.ACME = ACMEState{
	// 	Domain:        certificate.Domain,
	// 	CertURL:       certificate.CertURL,
	// 	CertStableURL: certificate.CertStableURL,
	//
	// 	PrivateKey:        certificate.PrivateKey,
	// 	Certificate:       certificate.Certificate,
	// 	IssuerCertificate: certificate.IssuerCertificate,
	// 	CSR:               certificate.CSR,
	// }
	// certificate, err := client.Certificate.Renew()
	// if err != nil {
	// 	err = CertificateObtain.Wrap(err, "could not obtain certifiate through ACME")
	// 	return
	// }

	return
}
