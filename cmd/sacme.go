package main

import (
	"flag"
	"fmt"
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

func removeUnmatchedInstalls(domain sacme.Domain, state *sacme.State) {
	for _, i := range state.Installs {
		matches := slices.ContainsFunc(domain.Installs, i.Matches)
		fmt.Println("diocane match", matches)
		os.Exit(69)
	}
}

func main() {
	domainsPath := flag.String("domains-path", sacme.DEFAULT_DOMAIN_PATH, "path containing domain definition files")
	stateStorePath := flag.String("state-store-path", sacme.DEFAULT_STATE_STORE_PATH, "path containing the state of certificate renewal")
	flag.Parse()

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
		slog.Info("loaded certificate", "notBefore", certificate.NotBefore, "now", now, "notAfter", certificate.NotAfter)
		remainingTime := certificate.NotAfter.Sub(now)

		if remainingTime < 0 {
			obtainCertificate(domain, state)
			newCertificate = true
		} else if remainingTime <= sacme.RENEW_DAYS_BEOFRE {
			renewCertificate(domain, state)
			newCertificate = true
		}

		if newCertificate {
			slog.Info("saving state")
			err = store.Store(domain, state)
			if err != nil {
				slog.Error("error while saving updated state", "err", err)
				os.Exit(8)
			}

			// TODO: remove all old install!
			removeUnmatchedInstalls(domain, state)
		}

		// if !newCertificate, bring install state up to definition
		// find installs to remove: i.e., missing in new install definition
		// next, install new definitions
		// to find installs to remove:
		// oi = set of old installs (state), ni = set of new installs
		// for i in oi:
		//   matches = false
		//   for i' in ni unless matches:
		//     if i matches i':
		//       matches = true
		//    if not matches:
		//      remove!
	}
}
