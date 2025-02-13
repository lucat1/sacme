package sacme

import "github.com/joomcode/errorx"

// Domain parsing errors/namespace/traits
var DomainNamespace = errorx.NewNamespace("domain")
var ValidateDomainTrait = errorx.RegisterTrait("validate_domain")
var ParseDomainTrait = errorx.RegisterTrait("parse_domain")

var InvalidDirectory = errorx.NewType(DomainNamespace, "invalid_directory", ValidateDomainTrait)

var InvalidPath = errorx.NewType(DomainNamespace, "invalid_path", ValidateDomainTrait)
var InvalidPerm = errorx.NewType(DomainNamespace, "invalid_perm", ValidateDomainTrait)
var InvalidOwner = errorx.NewType(DomainNamespace, "invalid_owner", ValidateDomainTrait)
var InvalidGroup = errorx.NewType(DomainNamespace, "invalid_group", ValidateDomainTrait)

var InvalidInstall = errorx.NewType(DomainNamespace, "invaild_install", ValidateDomainTrait)
var InvalidAccount = errorx.NewType(DomainNamespace, "invaild_account", ValidateDomainTrait)
var InvalidDomain = errorx.NewType(DomainNamespace, "invaild_domain", ValidateDomainTrait)

var InvalidRawDomain = errorx.NewType(DomainNamespace, "invaild_raw_domain", ParseDomainTrait)
