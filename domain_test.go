package sacme_test

import (
	"fmt"
	"os/user"
	"testing"

	"github.com/lucat1/sacme"
	"github.com/stretchr/testify/assert"
)

func ValidRawDomain(t *testing.T) (rawDomain string, u *user.User, g *user.Group) {
	u, e := user.Current()
	assert.Nil(t, e)
	assert.NotEmpty(t, u.Username)
	grps, e := u.GroupIds()
	assert.Nil(t, e)
	assert.True(t, len(grps) > 0)
	g, e = user.LookupGroupId(grps[0])
	assert.Nil(t, e)
	assert.NotEmpty(t, g.Name)

	rawDomain = fmt.Sprintf(`
domain = "example.com"

[account]
email = "root@example.com"

[[installs]]

[installs.key]
path = "/test/path.key"
perm = "0600"
owner = "%s"
group = "%s"

[installs.crt]
path = "/test/path.crt"
perm = "0644"
owner = "%s"
group = "%s"
  `, u.Username, g.Name, u.Username, g.Name)
	return
}

func TestParseDomainCorrect(t *testing.T) {
	rawDomain, u, g := ValidRawDomain(t)
	d, err := sacme.ParseDomain([]byte(rawDomain))
	assert.Nil(t, err)
	assert.NotNil(t, d)

	assert.Equal(t, "example.com", d.Domain)

	assert.Equal(t, "root@example.com", d.Account.Email)
	assert.Equal(t, sacme.DEFAULT_DIRECTORY, d.Account.Directroy.String())

	assert.Len(t, d.Installs, 1)
	inst0 := d.Installs[0]
	assert.EqualValues(t, &sacme.PathPerm{
		Path:  "/test/path.key",
		Perm:  0600,
		Owner: u,
		Group: g,
	}, inst0.Key)
	assert.EqualValues(t, &sacme.PathPerm{
		Path:  "/test/path.crt",
		Perm:  0644,
		Owner: u,
		Group: g,
	}, inst0.Crt)
	assert.Equal(t, sacme.DEFAULT_AUTHENTICATION_METHOD, d.Authentication.Method)
	assert.Len(t, d.Authentication.Options, len(sacme.DEFAULT_AUTHENTICATION_OPTIONS[d.Authentication.Method]))
}
