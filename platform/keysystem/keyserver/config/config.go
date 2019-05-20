package config

import (
	"github.com/sipb/homeworld/platform/keysystem/keyserver/account"
	"github.com/sipb/homeworld/platform/keysystem/keyserver/authorities"
)

type ConfigAuthority struct {
	Type      string
	Key       string
	Cert      string
	PresentAs []string
}

type ConfigGrant struct {
	Group        *account.Group
	Privilege    string
	Scope        *account.Group
	Authority    authorities.Authority
	IsHost       bool
	Lifespan     string
	CommonName   string
	AllowedNames []string
	Contents     string
}
