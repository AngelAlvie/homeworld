package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/sipb/homeworld/platform/keysystem/keyserver/account"
	"github.com/sipb/homeworld/platform/keysystem/keyserver/authorities"
)

type CompiledGrant struct {
	Privilege    string
	Scope        *account.Group
	Authority    authorities.Authority
	IsHost       bool
	Lifespan     time.Duration
	CommonName   string
	AllowedNames []string
	Contents     string
}

func (grant *CompiledGrant) CompileToPrivilege(context *Context) (account.Privilege, error) {
	switch grant.Privilege {
	case "bootstrap-account":
		if grant.CommonName != "" || grant.AllowedNames != nil || grant.Contents != "" || grant.Authority != nil {
			return nil, errors.New("extraneous parameter(s) provided to bootstrap-account")
		}
		if grant.Scope == nil || grant.Lifespan == 0 {
			return nil, errors.New("missing parameter(s) to bootstrap-account")
		}
		return account.NewBootstrapPrivilege(grant.Scope, grant.Lifespan, context.TokenVerifier.Registry)
	case "sign-ssh":
		if grant.Scope != nil || grant.Contents != "" {
			return nil, errors.New("extraneous parameter(s) provided to sign-ssh")
		}
		if grant.Authority == nil || grant.Lifespan == 0 || grant.CommonName == "" || grant.AllowedNames == nil {
			return nil, errors.New("missing parameter(s) to sign-ssh")
		}
		return account.NewSSHGrantPrivilege(grant.Authority, grant.IsHost, grant.Lifespan, grant.CommonName, grant.AllowedNames)
	case "sign-tls":
		if grant.Scope != nil || grant.Contents != "" {
			return nil, errors.New("extraneous parameter(s) provided to sign-tls")
		}
		if grant.Authority == nil || grant.Lifespan == 0 || grant.CommonName == "" {
			return nil, errors.New("missing parameter(s) to sign-tls")
		}
		return account.NewTLSGrantPrivilege(grant.Authority, grant.IsHost, grant.Lifespan, grant.CommonName, grant.AllowedNames)
	case "impersonate":
		if grant.Authority != nil || grant.CommonName != "" || grant.AllowedNames != nil || grant.Lifespan != 0 || grant.Contents != "" {
			return nil, errors.New("extraneous parameter(s) provided to impersonate")
		}
		if grant.Scope == nil {
			return nil, errors.New("missing parameter(s) to impersonate")
		}
		return account.NewImpersonatePrivilege(context.GetAccount, grant.Scope)
	case "construct-configuration":
		if grant.Scope != nil || grant.CommonName != "" || grant.AllowedNames != nil || grant.Lifespan != 0 || grant.Authority != nil {
			return nil, errors.New("extraneous parameter(s) provided to construct-configuration")
		}
		if grant.Contents == "" {
			return nil, errors.New("missing parameter(s) to construct-configuration")
		}
		return account.NewConfigurationPrivilege(grant.Contents)
	case "fetch-key":
		if grant.Scope != nil || grant.CommonName != "" || grant.AllowedNames != nil || grant.Lifespan != 0 || grant.Contents != "" {
			return nil, errors.New("extraneous parameter(s) provided to fetch-key")
		}
		if grant.Authority == nil {
			return nil, errors.New("missing parameter(s) to fetch-key")
		}
		return account.NewFetchKeyPrivilege(grant.Authority)
	default:
		return nil, fmt.Errorf("no such privilege kind: %s", grant.Privilege)
	}
}
