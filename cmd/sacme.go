package main

import (
	"flag"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/lucat1/sacme"
	"github.com/warpfork/go-fsx/osfs"
)

// checkForDuplicateDomains checks if any domain definition are duplicate (i.e.,
// are for the same domain name) and returns the duplicate record if found.
func checkForDuplicateDomains(domains []sacme.Domain) *string {
	m := map[string]bool{}
	for _, domain := range domains {
		if m[domain.Domain] {
			return &domain.Domain
		}
		m[domain.Domain] = true
	}

	return nil
}

func obtainCertificate(domain sacme.Domain, state *sacme.State) {
	slog.Info("obtaining certificate")

	err := sacme.ObtainCertificate(domain, state)
	if err != nil {
		slog.Error("error while obtaining certificate with ACME", "err", err)
		os.Exit(4)
	}

	slog.Info("obtained certificate")
}

func renewCertificate(domain sacme.Domain, state *sacme.State) {
	slog.Info("renewing certificate")

	err := sacme.RenewCertificate(domain, state)
	if err != nil {
		slog.Error("error while renewing certificate with ACME", "err", err)
		os.Exit(7)
	}

	slog.Info("renewed certificate")
}

func saveState(store *sacme.StateStore, domain sacme.Domain, state *sacme.State, cause string) {
	slog.Info("saving state", "cause", cause)
	err := store.Store(domain, state)
	if err != nil {
		slog.Error("error while saving updated state", "err", err)
		os.Exit(8)
	}

	slog.Info("state saved", "cause", cause)
}

func main() {
	domainsPath := flag.String("domains-path", sacme.DEFAULT_DOMAIN_PATH, "path containing domain definition files")
	stateStorePath := flag.String("state-store-path", sacme.DEFAULT_STATE_STORE_PATH, "path containing the state of certificate renewal")
	logLevel := flag.Int("log-level", sacme.DEFAULT_LOG_LEVEL, "verbosity of log output: debug (-4), info (0), warn (4), error (8)")
	flag.Parse()

	rootFS := osfs.DirFS("/")

	slog := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.Level(*logLevel),
	}))

	domains, err := sacme.LoadDomains(os.DirFS(*domainsPath))
	if err != nil {
		slog.Error("could not load configured domains", "err", err)
		os.Exit(1)
	}

	slog.Info("loaded domains", "len", len(domains))
	for _, domain := range domains {
		slog.Info("definition for", "domain", domain.Domain, "account", domain.Account, "authentication", domain.Authentication)
	}

	duplicate := checkForDuplicateDomains(domains)
	if duplicate != nil {
		slog.Error("duplicate domain", "domain", *duplicate)
		os.Exit(2)
	}

	store := sacme.NewStateStore(osfs.DirFS(*stateStorePath))
	for _, domain := range domains {
		slog := slog.With("domain", domain.Domain)

		slog.Info("processing domain")

		state, err := store.Load(domain)
		if err != nil {
			slog.Error("could not load domain state", "err", err)
			os.Exit(3)
		}

		slog.Info("loaded domain state", "account", state.Account)

		if !state.IsRegistered() {
			slog.Info("registering account", "email", domain.Account.Email)

			err = sacme.RegisterAccount(domain, state)
			if err != nil {
				slog.Error("could not register ACME account", "err", err)
				os.Exit(3)
			}

			slog.Info("registered account")
		}

		newCertificate := false
		if state.ACME.Empty() {
			obtainCertificate(domain, state)
			newCertificate = true
		}

		certificates, err := state.ACME.Certificates()
		if err != nil {
			slog.Error("could not parse certificate bundle", "err", err)
			os.Exit(6)
		}
		certificate := certificates[0]
		now := time.Now()
		elapsedTime := now.Sub(certificate.NotBefore)
		duration := certificate.NotAfter.Sub(certificate.NotBefore)
		halfTime := duration / 2
		slog.Info("loaded certificate", "notBefore", certificate.NotBefore, "now", now, "notAfter", certificate.NotAfter, "elapsedtime", elapsedTime, "halfTime", halfTime)

		if elapsedTime >= duration {
			obtainCertificate(domain, state)
			newCertificate = true
		} else if elapsedTime >= halfTime {
			renewCertificate(domain, state)
			newCertificate = true
		}

		if newCertificate {
			saveState(&store, domain, state, "new_certificate")
		}

		installs := []sacme.InstallState{}
		modifiedInstalls := false
		if !newCertificate {
			// If we haven't obtained a nwe certificate, then old installs
			// may be still relevant. Here we filter out installs and remove old files
			for _, i := range state.Installs {
				matches := slices.ContainsFunc(domain.Installs, i.Matches)
				slog.Debug("installed install matches", "install", i, "matches", matches)
				if !matches {
					err := i.Uninstall(rootFS)
					if err != nil {
						slog.Error("could not uninstall files", "err", err)
						os.Exit(9)
					}
					slog.Info("uninstalled", "key", i.Key, "crt", i.Crt, "ca", i.CA, "concat", i.Concat)
					modifiedInstalls = true
				} else {
					installs = append(installs, i)
				}
			}
		}

		// Install new installs
		for _, i := range domain.Installs {
			matches := slices.ContainsFunc(installs, i.Matches)
			slog.Debug("defined install matches", "install", i, "matches", matches)
			if !matches {
				is, err := i.Install(rootFS, state)
				if err != nil {
					slog.Error("could not install files", "err", err)
					os.Exit(10)
				}
				slog.Info("installed", "key", is.Key, "crt", is.Crt, "ca", is.CA, "concat", is.Concat)
				modifiedInstalls = true
				installs = append(installs, *is)
			}
		}

		if modifiedInstalls {
			state.Installs = installs
			saveState(&store, domain, state, "install")
		}

		slog.Info("finished processing")
	}
}
