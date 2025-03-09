package webroot

import "golang.org/x/exp/slog"

type WebrootProvider struct {
	path string
}

func NewWebrootProvider(path string) *WebrootProvider {
	// TOOD: also take in user/group/mode, like installs!
	return &WebrootProvider{
		path: path,
	}
}

func (wp *WebrootProvider) Present(domain, token, keyAuth string) (err error) {
	slog.Info("Present called", "domain", domain, "token", token, "keyAuth", keyAuth)
	// TODO: write file `token` with content `keyAuth`. Recycle install method?
	return
}

func (wp *WebrootProvider) CleanUp(domain, token, keyAuth string) (err error) {
	slog.Info("CleanUp called", "domain", domain, "token", token, "keyAuth", keyAuth)
	// Unlink `token` file. That's it.
	return
}
