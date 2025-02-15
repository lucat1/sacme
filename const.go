package sacme

const DOMAIN_FILE_SUFFIX = ".toml"

const DEFAULT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
const DEFAULT_DOMAIN_PATH = "/etc/sacme"

var VALID_AUTHENTICATION_METHODS = map[string]bool{
	"http-01/standalone": true,
	"http-01/webroot":    true,
	"dns-01/acmedns":     true,
}

const DEFAULT_AUTHENTICATION_METHOD = "http-01/standalone"
