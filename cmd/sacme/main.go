package main

import (
	"flag"
	"os"
	"os/exec"
	"time"

	"golang.org/x/exp/slog"

	"github.com/lucat1/sacme"
	fs "github.com/spf13/afero"
)

// Taken from go builtin's "slices" module, which is not available in Go1.19
// Copyright 2021 The Go Authors. All rights reserved.
func IndexFunc[S ~[]E, E any](s S, f func(E) bool) int {
	for i := range s {
		if f(s[i]) {
			return i
		}
	}
	return -1
}

func ContainsFunc[S ~[]E, E any](s S, f func(E) bool) bool {
	return IndexFunc(s, f) >= 0
}

// End of section copied from go's slices module

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

func obtainCertificate(slog *slog.Logger, domain sacme.Domain, state *sacme.State, rootFS fs.Fs) {
	slog.Info("obtaining certificate")

	err := sacme.ObtainCertificate(domain, state, rootFS)
	if err != nil {
		slog.Error("error while obtaining certificate with ACME", err)
		os.Exit(4)
	}

	slog.Info("obtained certificate")
}

func renewCertificate(slog *slog.Logger, domain sacme.Domain, state *sacme.State, rootFS fs.Fs) {
	slog.Info("renewing certificate")

	err := sacme.RenewCertificate(domain, state, rootFS)
	if err != nil {
		slog.Error("error while renewing certificate with ACME", err)
		os.Exit(7)
	}

	slog.Info("renewed certificate")
}

func saveState(slog *slog.Logger, store *sacme.StateStore, domain sacme.Domain, state *sacme.State, cause string) {
	slog.Info("saving state", "cause", cause)
	err := store.Store(domain, state)
	if err != nil {
		slog.Error("error while saving updated state", err)
		os.Exit(8)
	}

	slog.Info("state saved", "cause", cause)
}

func uninstall(slog *slog.Logger, i sacme.InstallState, rootFS fs.Fs) {
	err := i.Uninstall(rootFS)
	if err != nil {
		slog.Error("could not uninstall files", err)
		os.Exit(9)
	}
	slog.Info("uninstalled", "key", i.Key, "crt", i.Crt, "ca", i.CA, "concat", i.Concat)
}

func main() {
	domainsPath := flag.String("domains-path", sacme.DEFAULT_DOMAIN_PATH, "path containing domain definition files")
	stateStorePath := flag.String("state-store-path", sacme.DEFAULT_STATE_STORE_PATH, "path containing the state of certificate renewal")
	skipHooks := flag.Bool("skip-hooks", sacme.DEFAULT_SKIP_HOOKS, "wether to skip install hooks")
	// TODO: when slog is upgraded, restore the logic to set the log level
	// logLevel := flag.Int("log-level", sacme.DEFAULT_LOG_LEVEL, "verbosity of log output: debug (-4), info (0), warn (4), error (8)")
	flag.Parse()

	rootFS := fs.NewOsFs()

	// slog := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	// 	Level: slog.Level(*logLevel),
	// }))
	slog := slog.New(slog.NewTextHandler(os.Stderr))

	domains, err := sacme.LoadDomains(os.DirFS(*domainsPath))
	if err != nil {
		slog.Error("could not load configured domains", err)
		os.Exit(1)
	}

	slog.Info("loaded domains", "len", len(domains))
	for _, domain := range domains {
		slog.Info("definition for", "domain", domain.Domain, "account", domain.Account, "authentication", domain.Authentication)
	}

	duplicate := checkForDuplicateDomains(domains)
	if duplicate != nil {
		slog.Error("duplicate domain", nil, "domain", *duplicate)
		os.Exit(2)
	}

	store := sacme.NewStateStore(fs.NewBasePathFs(rootFS, *stateStorePath))
	modified := false
	for _, domain := range domains {
		slog := slog.With("domain", domain.Domain)

		slog.Info("processing domain")

		state, err := store.Load(domain)
		if err != nil {
			slog.Error("could not load domain state", err)
			os.Exit(3)
		}

		slog.Info("loaded domain state", "account", state.Account)

		if !state.IsRegistered() {
			slog.Info("registering account", "email", domain.Account.Email)

			err = sacme.RegisterAccount(domain, state)
			if err != nil {
				slog.Error("could not register ACME account", err)
				os.Exit(3)
			}

			slog.Info("registered account")
		}

		newCertificate := false
		if state.ACME.Empty() {
			obtainCertificate(&slog, domain, state, rootFS)
			newCertificate = true
		}

		certificates, err := state.ACME.Certificates()
		if err != nil {
			slog.Error("could not parse certificate bundle", err)
			os.Exit(6)
		}
		certificate := certificates[0]
		now := time.Now()
		elapsedTime := now.Sub(certificate.NotBefore)
		duration := certificate.NotAfter.Sub(certificate.NotBefore)
		halfTime := duration / 2
		slog.Info("loaded certificate", "notBefore", certificate.NotBefore, "now", now, "notAfter", certificate.NotAfter, "elapsedtime", elapsedTime, "halfTime", halfTime)

		if elapsedTime >= duration {
			obtainCertificate(&slog, domain, state, rootFS)
			newCertificate = true
		} else if elapsedTime >= halfTime {
			renewCertificate(&slog, domain, state, rootFS)
			newCertificate = true
		}

		if newCertificate {
			saveState(&slog, &store, domain, state, "new_certificate")
		}

		installs := []sacme.InstallState{}
		modifiedInstalls := false
		if !newCertificate {
			// If we haven't obtained a nwe certificate, then old installs
			// may be still relevant. Here we filter out installs and remove old files
			for _, i := range state.Installs {
				matches := ContainsFunc(domain.Installs, i.Matches)
				slog.Debug("installed install matches", "install", i, "matches", matches)
				if !matches {
					uninstall(&slog, i, rootFS)
					modifiedInstalls = true
				} else {
					installs = append(installs, i)
				}
			}
		} else {
			// If we've obtained a new certificate all old files can be uninstalled
			for _, i := range state.Installs {
				uninstall(&slog, i, rootFS)
				modifiedInstalls = true
			}
		}

		slog.Debug("valid current install paths", "count", len(installs))

		// Install new installs
		for _, i := range domain.Installs {
			matches := ContainsFunc(installs, i.Matches)
			slog.Debug("defined install matches", "install", i, "matches", matches)
			if !matches {
				is, err := i.Install(rootFS, state)
				if err != nil {
					slog.Error("could not install files", err)
					os.Exit(10)
				}
				slog.Info("installed", "key", is.Key, "crt", is.Crt, "ca", is.CA, "concat", is.Concat)
				modifiedInstalls = true
				installs = append(installs, *is)

				if len(i.Hooks) > 0 {
					if *skipHooks {
						slog.Info("avoiding running hooks", "hooks", i.Hooks)
					} else {
						slog.Info("running hooks for install", "hooks", i.Hooks)
						for _, hook := range i.Hooks {
							slog := slog.With("hook", hook)
							cmd := exec.Command(sacme.DEFAULT_SHELL, "-c", hook)
							stdout, err := cmd.Output()
							if err != nil {
								slog.Error("error while running hook", err)
								os.Exit(11)
							}

							slog.Info("ran hook", "stdout", string(stdout))
						}
					}
				}
			}
		}

		if modifiedInstalls {
			state.Installs = installs
			saveState(&slog, &store, domain, state, "install")
		}

		modified = modified || newCertificate || modifiedInstalls
		slog.Info("finished processing")
	}

	if !modified {
		slog.Info("unchanged")
	}

	os.Exit(0)
}
