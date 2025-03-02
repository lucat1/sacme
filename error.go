package sacme

import "errors"

// Domain parsing errors
var MissingEmail = errors.New("missing_email")
var InvalidKeyType = errors.New("invalid_key_type")
var InvalidDirectory = errors.New("invalid_directory")

var InvalidMethod = errors.New("invalid_method")
var InvalidOption = errors.New("invalid_option")

var InvalidPath = errors.New("invalid_path")
var InvalidPerm = errors.New("invalid_perm")
var InvalidOwner = errors.New("invalid_owner")
var InvalidGroup = errors.New("invalid_group")

var InvalidAccount = errors.New("invaild_account")
var InvalidAuthentication = errors.New("invaild_authentication")
var InvalidInstall = errors.New("invaild_install")
var InvalidDomain = errors.New("invaild_domain")

var InvalidRawDomain = errors.New("invaild_raw_domain")

// Loading multiple domains files from the configuration directory
var ReadDomainsDirectory = errors.New("read_domains_directory")
var ReadDomainFile = errors.New("read_domain_file")
var LoadDomain = errors.New("load_domain")

// ACME errors
var CreateClient = errors.New("create_client")

var AccountAlreadyRegistered = errors.New("account_already_registered")
var AccountRegistration = errors.New("account_registraiton")

var ProviderHTTP01Standalone = errors.New("provider_http01_standalone")
var ProviderSetup = errors.New("provider_setup")
var CertificateObtain = errors.New("certificate_obtain")
var CertificateRenew = errors.New("certificate_renew")

// State erorrs
var GenerateKey = errors.New("generate_key")
var NewStateError = errors.New("new_state")
var DecodeState = errors.New("decode_state")

var OpenStoreFile = errors.New("open_store_file")
var EncodeState = errors.New("encode_state")

var MissingCertificate = errors.New("missing_certificate")
var ParseCertificates = errors.New("parse_certificates")

var InstallFile = errors.New("install_file")
var RemoveFile = errors.New("remove_file")
var WriteToFile = errors.New("write_to_file")
var UnfinishedWrite = errors.New("unfinished_write")
