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

	assert.Equal(t, d.Domain, "example.com")

	assert.Equal(t, d.Account.Email, "root@example.com")
	assert.Equal(t, d.Account.Directroy.String(), sacme.DEFAULT_DIRECTORY)

	assert.Len(t, d.Installs, 1)
	inst0 := d.Installs[0]
	assert.EqualValues(t, inst0.Key, &sacme.PathPerm{
		Path:  "/test/path.key",
		Perm:  0600,
		Owner: u,
		Group: g,
	})
	assert.EqualValues(t, inst0.Crt, &sacme.PathPerm{
		Path:  "/test/path.crt",
		Perm:  0644,
		Owner: u,
		Group: g,
	})
}
