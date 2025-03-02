package sacme

import "golang.org/x/exp/slog"

const DOMAIN_FILE_SUFFIX = ".toml"

const DEFAULT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
const DEFAULT_DOMAIN_PATH = "/etc/sacme"
const DEFAULT_STATE_STORE_PATH = "/var/lib/sacme"
const DEFAULT_LOG_LEVEL = int(slog.LevelInfo)

type KeyType string

// TODO: differentiate between KeyType for the certificate and for the accoutn
// private key. Ideally we want to use ED25519
const (
	KEY_TYPE_P256    = KeyType("p256")
	KEY_TYPE_RSA2048 = KeyType("rsa2048")
	KEY_TYPE_RSA4096 = KeyType("rsa4096")
)

var VALID_KEY_TYPES = map[KeyType]bool{
	KEY_TYPE_P256:    true,
	KEY_TYPE_RSA2048: true,
	KEY_TYPE_RSA4096: true,
}

const DEFAULT_KEY_TYPE = KEY_TYPE_P256

type AuthenticationMethod string

const (
	AUTHENTICATION_METHOD_HTTP01_STANDALONE = AuthenticationMethod("http-01/standalone")
	AUTHENTICATION_METHOD_HTTP01_WEBROOT    = AuthenticationMethod("http-01/webroot")
	AUTHENTICATION_METHOD_DNS01_ACMEDNS     = AuthenticationMethod("dns-01/acmedns")
)

var VALID_AUTHENTICATION_METHODS = map[AuthenticationMethod]bool{
	AUTHENTICATION_METHOD_HTTP01_STANDALONE: true,
	AUTHENTICATION_METHOD_HTTP01_WEBROOT:    true,
	AUTHENTICATION_METHOD_DNS01_ACMEDNS:     true,
}

const DEFAULT_AUTHENTICATION_METHOD = AUTHENTICATION_METHOD_HTTP01_STANDALONE

const (
	// For http-01/standalone
	AUTHENTICATION_OPTION_INTERFACE = "interface"
	AUTHENTICATION_OPTION_PORT      = "port"

	// For http-01/webroot
	AUTHENTICATION_OPTION_PATH = "path"
)

var VALID_AUTHENTICATION_OPTIONS = map[AuthenticationMethod]map[string]bool{
	AUTHENTICATION_METHOD_HTTP01_STANDALONE: map[string]bool{
		AUTHENTICATION_OPTION_INTERFACE: true,
		AUTHENTICATION_OPTION_PORT:      true,
	},
	AUTHENTICATION_METHOD_HTTP01_WEBROOT: map[string]bool{
		AUTHENTICATION_OPTION_PATH: true,
	},
	AUTHENTICATION_METHOD_DNS01_ACMEDNS: map[string]bool{},
}

var DEFAULT_AUTHENTICATION_OPTIONS = map[AuthenticationMethod]map[string]string{
	AUTHENTICATION_METHOD_HTTP01_STANDALONE: map[string]string{
		AUTHENTICATION_OPTION_INTERFACE: "",
		AUTHENTICATION_OPTION_PORT:      "80",
	},
	AUTHENTICATION_METHOD_HTTP01_WEBROOT: map[string]string{
		AUTHENTICATION_OPTION_PATH: "",
	},
	AUTHENTICATION_METHOD_DNS01_ACMEDNS: map[string]string{},
}
