package sacme_test

import (
	"testing"
	"testing/fstest"

	"github.com/lucat1/sacme"
	"github.com/stretchr/testify/assert"
)

func TestLoadDomains(t *testing.T) {
	rawDomain, _, _ := ValidRawDomain(t)
	fs := fstest.MapFS{
		"example.com.toml": &fstest.MapFile{
			Data: []byte(rawDomain),
		},
	}

	domains, err := sacme.LoadDomains(fs)
	assert.Nil(t, err)
	assert.Len(t, domains, 1)
	d := domains[0]
	assert.EqualValues(t, d.Domains, []string{"example.com"})
}
