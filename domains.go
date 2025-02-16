package sacme

import (
	fs "github.com/warpfork/go-fsx"
	"strings"
)

// ListDomainFiles returns a list of paths of files which *should* contain a
// domain definition
func ListDomainFiles(f fs.FS) (paths []string, err error) {
	entries, err := fs.ReadDir(f, ".")
	if err != nil {
		err = ReadDomainsDirectory.Wrap(err, "could not list domains directory")
		return
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), DOMAIN_FILE_SUFFIX) {
			paths = append(paths, entry.Name())
		}
	}
	return
}

// LoadDomains loads all domain definitions from all eligible domain files
// found in the provided filesystem.
// As soon as an error is encountered the function aborts.
func LoadDomains(f fs.FS) (domains []Domain, err error) {
	files, err := ListDomainFiles(f)
	if err != nil {
		return
	}

	for _, file := range files {
		var content []byte
		content, err = fs.ReadFile(f, file)
		if err != nil {
			err = ReadDomainFile.Wrap(err, "could not read domain file")
			return
		}

		var domain *Domain
		domain, err = ParseDomain(content)
		if err != nil {
			err = LoadDomain.Wrap(err, "could not parse domain")
			return
		}
		domains = append(domains, *domain)
	}

	return
}
