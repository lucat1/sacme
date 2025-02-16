package sacme

import "github.com/joomcode/errorx"

// Domain parsing errors/namespace/traits
var DomainNamespace = errorx.NewNamespace("domain")
var ValidateDomainTrait = errorx.RegisterTrait("validate_domain")
var ParseDomainTrait = errorx.RegisterTrait("parse_domain")

var MissingEmail = errorx.NewType(DomainNamespace, "missing_email", ValidateDomainTrait)
var InvalidKeyType = errorx.NewType(DomainNamespace, "invalid_key_type", ValidateDomainTrait)
var InvalidDirectory = errorx.NewType(DomainNamespace, "invalid_directory", ValidateDomainTrait)

var InvalidMethod = errorx.NewType(DomainNamespace, "invalid_method", ValidateDomainTrait)
var InvalidOption = errorx.NewType(DomainNamespace, "invalid_option", ValidateDomainTrait)

var InvalidPath = errorx.NewType(DomainNamespace, "invalid_path", ValidateDomainTrait)
var InvalidPerm = errorx.NewType(DomainNamespace, "invalid_perm", ValidateDomainTrait)
var InvalidOwner = errorx.NewType(DomainNamespace, "invalid_owner", ValidateDomainTrait)
var InvalidGroup = errorx.NewType(DomainNamespace, "invalid_group", ValidateDomainTrait)

var InvalidAccount = errorx.NewType(DomainNamespace, "invaild_account", ValidateDomainTrait)
var InvalidAuthentication = errorx.NewType(DomainNamespace, "invaild_authentication", ValidateDomainTrait)
var InvalidInstall = errorx.NewType(DomainNamespace, "invaild_install", ValidateDomainTrait)
var InvalidDomain = errorx.NewType(DomainNamespace, "invaild_domain", ValidateDomainTrait)

var InvalidRawDomain = errorx.NewType(DomainNamespace, "invaild_raw_domain", ParseDomainTrait)

// Loading multiple domains files from the configuration directory
var DomainsNamespace = errorx.NewNamespace("domains")
var LoadDomainsTrait = errorx.RegisterTrait("load_domains")

var ReadDomainsDirectory = errorx.NewType(DomainsNamespace, "read_domains_directory", LoadDomainsTrait)
var ReadDomainFile = errorx.NewType(DomainsNamespace, "read_domain_file", LoadDomainsTrait)
var LoadDomain = errorx.NewType(DomainsNamespace, "load_domain", LoadDomainsTrait)

// ACME errors
var ACMENamespace = errorx.NewNamespace("acme")
var RegisterAccountTrait = errorx.RegisterTrait("register_account")
var ObtainCertificateTrait = errorx.RegisterTrait("obtain_certificate")

var CreateClient = errorx.NewType(ACMENamespace, "create_client", RegisterAccountTrait)

var AccountAlreadyRegistered = errorx.NewType(ACMENamespace, "account_already_registered", RegisterAccountTrait)
var AccountRegistration = errorx.NewType(ACMENamespace, "account_registraiton", RegisterAccountTrait)

var ProviderHTTP01Standalone = errorx.NewType(ACMENamespace, "provider_http01_standalone", ObtainCertificateTrait)
var ProviderSetup = errorx.NewType(ACMENamespace, "provider_setup", ObtainCertificateTrait)
var CertificateObtain = errorx.NewType(ACMENamespace, "certificate_obtain", ObtainCertificateTrait)

// State erorrs
var StateNamespace = errorx.NewNamespace("state")
var LoadTrait = errorx.RegisterTrait("load")
var StoreTrait = errorx.RegisterTrait("store")
var CertificatesTrait = errorx.RegisterTrait("certificates")

var GenerateKey = errorx.NewType(StateNamespace, "generate_key", LoadTrait)
var NewStateError = errorx.NewType(StateNamespace, "new_state", LoadTrait)
var DecodeState = errorx.NewType(StateNamespace, "decode_state", LoadTrait)

var OpenStoreFile = errorx.NewType(StateNamespace, "open_store_file", StoreTrait)
var EncodeState = errorx.NewType(StateNamespace, "encode_state", StoreTrait)

var MissingCertificate = errorx.NewType(StateNamespace, "missing_certificate", CertificatesTrait)
var ParseCertificates = errorx.NewType(StateNamespace, "parse_certificates", CertificatesTrait)
