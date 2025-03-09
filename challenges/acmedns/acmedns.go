package acmedns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"golang.org/x/exp/slog"
)

const (
	API_UPDATE_PATH = "update"
	API_USER_HEADER = "X-Api-User"
	API_KEY_HEADER  = "X-Api-Key"
)

type updateRequest struct {
	Subdomain string `json:"subdomain"`
	Token     string `json:"txt"`
}

type ACMEDNSProvider struct {
	endpoint  *url.URL
	username  string
	password  string
	subdomain string
}

func NewACMEDNSProvider(endpoint *url.URL, username, password, subdomain string) *ACMEDNSProvider {
	return &ACMEDNSProvider{
		endpoint:  endpoint,
		username:  username,
		password:  password,
		subdomain: subdomain,
	}
}

func (adp *ACMEDNSProvider) Present(domain, token, keyAuth string) (err error) {
	_, value := dns01.GetRecord(domain, keyAuth)
	slog.Info("serving token in acmedns", "domain", domain, "rawToken", token, "token", value, "subdomain", adp.subdomain)
	token = value

	reqBytes, err := json.Marshal(&updateRequest{
		Subdomain: adp.subdomain,
		Token:     token,
	})
	if err != nil {
		err = fmt.Errorf("could not marshal update request: %w", err)
		return
	}

	url := adp.endpoint.JoinPath(API_UPDATE_PATH)
	req, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(reqBytes))
	if err != nil {
		err = fmt.Errorf("error while constructing request for ACMEDNS update: %w", err)
		return
	}
	req.Header.Add(API_USER_HEADER, adp.username)
	req.Header.Add(API_KEY_HEADER, adp.password)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("error while sending request for ACMEDNS update: %w", err)
		return
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("could not read ACMEDNS response bytes: %w", err)
		return
	}

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("got status %d (expecting %d) for ACMEDNS update request: %s", res.StatusCode, http.StatusOK, string(resBytes))
		return
	}

	return
}

func (adp *ACMEDNSProvider) CleanUp(domain, token, keyAuth string) (err error) {
	slog.Info("removing token from acmedns", "domain", domain, "token", token, "subdomain", adp.subdomain)
	return
}
