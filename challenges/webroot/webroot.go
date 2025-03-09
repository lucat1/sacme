package webroot

import (
	"fmt"
	"path"

	"github.com/lucat1/sacme/pkg/file"
	fs "github.com/spf13/afero"
	"golang.org/x/exp/slog"
)

type WebrootProvider struct {
	fs fs.Fs
	pp *file.PathPerm
}

func NewWebrootProvider(fs fs.Fs, pp *file.PathPerm) *WebrootProvider {
	return &WebrootProvider{fs: fs, pp: pp}
}

func (wp *WebrootProvider) Present(domain, token, keyAuth string) (err error) {
	slog.Info("serving token in webroot", "domain", domain, "token", token, "webroot", wp.pp.Path)
	tokenPP := file.PathPerm{
		Path:  path.Join(wp.pp.Path, token),
		Owner: wp.pp.Owner,
		Group: wp.pp.Group,
		Perm:  wp.pp.Perm,
	}

	err = file.WriteFile(wp.fs, tokenPP, []byte(keyAuth), "token")
	if err != nil {
		err = fmt.Errorf("could not write token for webroot challange provider: %w", err)
		return
	}

	return
}

func (wp *WebrootProvider) CleanUp(domain, token, keyAuth string) (err error) {
	slog.Info("removing token in webroot", "domain", domain, "token", token, "webroot", wp.pp.Path)
	tokenPath := path.Join(wp.pp.Path, token)

	err = file.RemoveFile(wp.fs, tokenPath)
	if err != nil {
		err = fmt.Errorf("could not remove token for webroot challange provider: %w", err)
		return
	}

	return
}
