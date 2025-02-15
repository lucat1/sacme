package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/lucat1/sacme"
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

func main() {
	domainsPath := flag.String("domains-path", sacme.DEFAULT_DOMAIN_PATH, "path containing domain definition files")
	flag.Parse()

	fs := os.DirFS(*domainsPath)
	domains, err := sacme.LoadDomains(fs)
	if err != nil {
		slog.Error("could not load configured domains", "err", err)
		os.Exit(1)
	}

	slog.Info("loaded domains", "len", len(domains))
	for _, domain := range domains {
		slog.Info("definition for", "domain", domain.Domain)
	}

	duplicate := checkForDuplicateDomains(domains)
	if duplicate != nil {
		slog.Error("duplicate domain", "domain", *duplicate)
		os.Exit(1)
	}
}
