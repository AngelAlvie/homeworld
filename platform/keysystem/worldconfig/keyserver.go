package worldconfig

import (
	"fmt"
	"github.com/pkg/errors"
	"net"
	"os"
	"time"

	"github.com/sipb/homeworld/platform/keysystem/keyserver/account"
	"github.com/sipb/homeworld/platform/keysystem/keyserver/authorities"
	"github.com/sipb/homeworld/platform/keysystem/keyserver/config"
	"github.com/sipb/homeworld/platform/keysystem/keyserver/verifier"
	"github.com/sipb/homeworld/platform/keysystem/worldconfig/paths"
	"github.com/sipb/homeworld/platform/util/strutil"
)

type Groups struct {
	KerberosAccounts *account.Group
	RootAdmins       *account.Group
	Nodes            *account.Group
	SupervisorNodes  *account.Group
	WorkerNodes      *account.Group
	MasterNodes      *account.Group
}

func GenerateGroups(context *config.Context) Groups {
	kerberosAccountsGroup := &account.Group{
		Name: "kerberos-accounts",
	}
	nodesGroup := &account.Group{
		Name: "nodes",
	}
	groups := Groups{
		KerberosAccounts: kerberosAccountsGroup,
		Nodes:            nodesGroup,
		RootAdmins: &account.Group{
			Name:       "root-admins",
			SubgroupOf: kerberosAccountsGroup,
		},
		SupervisorNodes: &account.Group{
			Name:       "supervisor-nodes",
			SubgroupOf: nodesGroup,
		},
		WorkerNodes: &account.Group{
			Name:       "worker-nodes",
			SubgroupOf: nodesGroup,
		},
		MasterNodes: &account.Group{
			Name:       "master-nodes",
			SubgroupOf: nodesGroup,
		},
	}

	return groups
}

func GenerateAccounts(context *config.Context, conf *SpireSetup, groups Groups) error {
	var accounts []*account.Account

	// TODO: ensure that node hostnames are not duplicated

	for _, node := range conf.Nodes {
		var schedule string
		var group *account.Group
		if node.Kind == "worker" {
			schedule = "true"
			group = groups.WorkerNodes
		} else {
			schedule = "false"
			if node.Kind == "supervisor" {
				group = groups.SupervisorNodes
			} else if node.Kind == "master" {
				group = groups.MasterNodes
			} else {
				return fmt.Errorf("unrecognized kind of node: %s", node.Kind)
			}
		}

		limitIP := net.ParseIP(node.IP)
		if limitIP == nil {
			return fmt.Errorf("invalid IP address: %s", node.IP)
		}

		principal := node.Hostname + "." + conf.Cluster.ExternalDomain

		accounts = append(accounts, &account.Account{
			Principal: principal,
			Group:     group,
			LimitIP:   limitIP,
			Metadata: map[string]string{
				"ip":       node.IP,
				"hostname": node.Hostname,
				"schedule": schedule,
				"kind":     node.Kind,
			},
		})

		groups.Nodes.AllMembers = append(groups.Nodes.AllMembers, principal)
		group.AllMembers = append(group.AllMembers, principal)
	}

	// metrics principal used by homeworld-ssh-checker
	allAdmins := append([]string{"metrics@NONEXISTENT.REALM.INVALID"}, conf.RootAdmins...)

	for _, rootAdmin := range allAdmins {
		if rootAdmin == "" {
			return errors.New("cannot have an admin with an unnamed account")
		}
		// TODO: ensure that root admins are unique, including against the metrics admin
		accounts = append(accounts, &account.Account{
			Principal:         rootAdmin,
			DisableDirectAuth: true,
			Group:             groups.RootAdmins,
		})
		groups.RootAdmins.AllMembers = append(groups.RootAdmins.AllMembers, rootAdmin)
		groups.KerberosAccounts.AllMembers = append(groups.KerberosAccounts.AllMembers, rootAdmin)
	}

	if len(conf.RootAdmins) > 0 {
		for _, node := range conf.Nodes {
			if node.Kind == "supervisor" {
				principal := "host/" + node.Hostname + "." + conf.Cluster.ExternalDomain + "@" + conf.Cluster.KerberosRealm
				accounts = append(accounts, &account.Account{
					Principal:         principal,
					DisableDirectAuth: true,
					Group:             groups.KerberosAccounts,
				})
				groups.KerberosAccounts.AllMembers = append(groups.KerberosAccounts.AllMembers, principal)
			}
		}
	}

	for _, ac := range accounts {
		if ac.Metadata == nil {
			ac.Metadata = map[string]string{}
		}
		ac.Metadata["principal"] = ac.Principal
		context.Accounts[ac.Principal] = ac
	}
	return nil
}

type Authorities struct {
	Keygranting    *authorities.TLSAuthority
	ServerTLS      *authorities.TLSAuthority
	ClusterTLS     *authorities.TLSAuthority
	SshUser        *authorities.SSHAuthority
	SshHost        *authorities.SSHAuthority
	EtcdServer     *authorities.TLSAuthority
	EtcdClient     *authorities.TLSAuthority
	Kubernetes     *authorities.TLSAuthority
	ServiceAccount *authorities.StaticAuthority
}

func GenerateAuthorities(conf *SpireSetup) map[string]config.ConfigAuthority {
	var presentAs []string
	for _, node := range conf.Nodes {
		if node.Kind == "supervisor" {
			presentAs = append(presentAs, node.Hostname+"."+conf.Cluster.ExternalDomain)
		}
	}

	return map[string]config.ConfigAuthority{
		AuthenticationAuthority: {
			Type: "TLS",
			Key:  "keygrant.key",
			Cert: "keygrant.pem",
		},
		ServerTLS: {
			Type:      "TLS",
			Key:       "server.key",
			Cert:      "server.pem",
			PresentAs: presentAs,
		},
		"clustertls": {
			Type: "TLS",
			Key:  "cluster.key",
			Cert: "cluster.cert",
		},
		"ssh-user": {
			Type: "SSH",
			Key:  "ssh_user_ca",
			Cert: "ssh_user_ca.pub",
		},
		"ssh-host": {
			Type: "SSH",
			Key:  "ssh_host_ca",
			Cert: "ssh_host_ca.pub",
		},
		"etcd-server": {
			Type: "TLS",
			Key:  "etcd-server.key",
			Cert: "etcd-server.pem",
		},
		"etcd-client": {
			Type: "TLS",
			Key:  "etcd-client.key",
			Cert: "etcd-client.pem",
		},
		"kubernetes": {
			Type: "TLS",
			Key:  "kubernetes.key",
			Cert: "kubernetes.pem",
		},
		"serviceaccount": {
			Type: "static",
			Key:  "serviceaccount.key",
			Cert: "serviceaccount.pem",
		},
	}
}

func GenerateGrants(context *config.Context, conf *SpireSetup, groups Groups, auth Authorities) error {
	domain := conf.Cluster.ExternalDomain
	internalDomain := conf.Cluster.InternalDomain
	serviceAPI := conf.Addresses.ServiceAPI

	grants := map[string]config.ConfigGrant{
		// ADMIN ACCESS TO THE RUNNING CLUSTER

		"access-ssh": {
			Group:        groups.RootAdmins,
			Privilege:    "sign-ssh",
			Authority:    auth.SshUser,
			Lifespan:     "4h",
			IsHost:       false,
			CommonName:   "temporary-ssh-grant-(principal)",
			AllowedNames: []string{"root"},
		},

		"access-etcd": {
			Group:      groups.RootAdmins,
			Privilege:  "sign-tls",
			Authority:  auth.EtcdClient,
			Lifespan:   "4h",
			IsHost:     false,
			CommonName: "temporary-etcd-grant-(principal)",
		},

		"access-kubernetes": {
			Group:      groups.RootAdmins,
			Privilege:  "sign-tls",
			Authority:  auth.Kubernetes,
			Lifespan:   "4h",
			IsHost:     false,
			CommonName: "temporary-kube-grant-(principal)",
		},

		// MEMBERSHIP IN THE CLUSTER

		"bootstrap": {
			Group:     groups.RootAdmins,
			Privilege: "bootstrap-account",
			Scope:     groups.Nodes,
			Lifespan:  "1h",
		},

		"bootstrap-keyinit": {
			Group:     groups.SupervisorNodes,
			Privilege: "bootstrap-account",
			Scope:     groups.Nodes,
			Lifespan:  "1h",
		},

		"renew-keygrant": {
			Group:      groups.Nodes,
			Privilege:  "sign-tls",
			Authority:  auth.Keygranting,
			Lifespan:   "960h", // forty day lifespan
			IsHost:     false,
			CommonName: "(principal)",
		},

		"auth-to-kerberos": { // integration with kerberos gateway
			Group:     groups.SupervisorNodes,
			Privilege: "impersonate",
			Scope:     groups.KerberosAccounts,
		},

		// CONFIGURATION ENDPOINT

		"get-local-config": {
			Group:     groups.Nodes,
			Privilege: "construct-configuration",
			Contents: `# generated automatically by keyserver
HOST_NODE=(hostname)
HOST_DNS=(hostname).` + domain + `
HOST_IP=(ip)
SCHEDULE_WORK=(schedule)
KIND=(kind)`,
		},

		// SERVER CERTIFICATES

		"grant-ssh-host": {
			Group:      groups.Nodes,
			Privilege:  "sign-ssh",
			Authority:  auth.SshHost,
			Lifespan:   "1440h", // sixty day lifespan
			IsHost:     true,
			CommonName: "admitted-(principal)",
			AllowedNames: []string{
				"(hostname)." + domain,
				"(hostname)",
				"(ip)",
			},
		},

		"grant-kubernetes-master": {
			Group:      groups.MasterNodes,
			Privilege:  "sign-tls",
			Authority:  auth.Kubernetes,
			Lifespan:   "720h",
			IsHost:     true,
			CommonName: "kube-master-(hostname)",
			AllowedNames: []string{
				"(hostname)." + domain,
				"(hostname)",
				"kubernetes",
				"kubernetes.default",
				"kubernetes.default.svc",
				"kubernetes.default.svc." + internalDomain,
				"(ip)",
				serviceAPI,
			},
		},

		"grant-etcd-server": {
			Group:      groups.MasterNodes,
			Privilege:  "sign-tls",
			Authority:  auth.EtcdServer,
			Lifespan:   "720h", // thirty days
			IsHost:     true,
			CommonName: "etcd-server-(hostname)",
			AllowedNames: []string{
				"(hostname)." + domain,
				"(hostname)",
				"(ip)",
			},
		},

		"grant-registry-host": {
			Group:        groups.SupervisorNodes,
			Privilege:    "sign-tls",
			Authority:    auth.ClusterTLS,
			Lifespan:     "720h", // thirty days
			IsHost:       true,
			CommonName:   "homeworld-supervisor-(hostname)",
			AllowedNames: []string{"homeworld.private"},
		},

		// CLIENT CERTIFICATES

		"grant-kubernetes-worker": {
			Group:      groups.Nodes,
			Privilege:  "sign-tls",
			Authority:  auth.Kubernetes,
			Lifespan:   "720h",
			IsHost:     true,
			CommonName: "kube-worker-(hostname)",
			AllowedNames: []string{
				"(hostname)." + domain,
				"(hostname)",
				"(ip)",
			},
		},

		"grant-etcd-client": {
			Group:      groups.MasterNodes,
			Privilege:  "sign-tls",
			Authority:  auth.EtcdClient,
			Lifespan:   "720h",
			IsHost:     false,
			CommonName: "etcd-client-(hostname)",
			AllowedNames: []string{
				"(hostname)." + domain,
				"(hostname)",
				"(ip)",
			},
		},

		"fetch-serviceaccount-key": {
			Group:     groups.MasterNodes,
			Privilege: "fetch-key",
			Authority: auth.ServiceAccount,
		},
	}

	for api, grant := range grants {
		privileges := map[string]account.Privilege{}
		for _, accountname := range grant.Group.AllMembers {
			_, found := privileges[accountname]
			if found {
				return fmt.Errorf("duplicate account %s", accountname)
			}
			ac, found := context.Accounts[accountname]
			if !found {
				return fmt.Errorf("no such account %s", accountname)
			}
			cgrant, err := CompileGrant(grant, ac.Metadata, context)
			if err != nil {
				return err
			}
			priv, err := cgrant.CompileToPrivilege(context)
			if err != nil {
				return fmt.Errorf("%s (in grant %s for account %s)", err, api, accountname)
			}
			privileges[accountname] = priv
		}
		context.Grants[api] = config.Grant{api, grant.Group, privileges}
	}
	return nil
}

func CompileGrant(grant config.ConfigGrant, vars map[string]string, ctx *config.Context) (*config.CompiledGrant, error) {
	g := &config.CompiledGrant{
		Privilege: grant.Privilege,
		Scope:     grant.Scope,
		IsHost:    grant.IsHost,
		Authority: grant.Authority,
	}
	if grant.Lifespan != "" {
		lifespan, err := time.ParseDuration(grant.Lifespan)
		if err != nil {
			return nil, err
		}
		if lifespan <= 0 {
			return nil, errors.New("nonpositive lifespans are not supported")
		}
		g.Lifespan = lifespan
	}
	if grant.CommonName != "" {
		commonname, err := strutil.SubstituteVars(grant.CommonName, vars)
		if err != nil {
			return nil, err
		}
		g.CommonName = commonname
	}
	if grant.AllowedNames != nil {
		allowednames, err := strutil.SubstituteAllVars(grant.AllowedNames, vars)
		if err != nil {
			return nil, err
		}
		g.AllowedNames = allowednames
	}
	if grant.Contents != "" {
		contents, err := strutil.SubstituteVars(grant.Contents, vars)
		if err != nil {
			return nil, err
		}
		g.Contents = contents
	}
	return g, nil
}

func ValidateStaticFiles(context *config.Context) error {
	for _, static := range context.StaticFiles {
		// check for existence
		openfile, err := os.Open(static.Filepath)
		if err != nil {
			return err
		}
		err = openfile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

const AuthorityKeyDirectory = "/etc/homeworld/keyserver/authorities/"
const AuthenticationAuthority = "keygranting"
const ServerTLS = "servertls"

func GenerateConfig() (*config.Context, error) {
	conf, err := LoadSpireSetup(paths.SpireSetupPath)
	if err != nil {
		return nil, err
	}

	context := &config.Context{
		TokenVerifier: verifier.NewTokenVerifier(),
		StaticFiles: map[string]config.StaticFile{
			"cluster.conf": {
				Filename: "cluster.conf",
				Filepath: "/etc/homeworld/keyserver/static/cluster.conf",
			},
			"machine.list": {
				Filename: "machine.list",
				Filepath: "/etc/homeworld/keyserver/static/machine.list",
			},
		},
		Authorities: map[string]authorities.Authority{},
		Accounts:    map[string]*account.Account{},
		Grants:      map[string]config.Grant{},
	}
	err = ValidateStaticFiles(context)
	if err != nil {
		return nil, err
	}
	for name, authority := range GenerateAuthorities(conf) {
		loaded, err := authority.Load(AuthorityKeyDirectory)
		if err != nil {
			return nil, err
		}
		context.Authorities[name] = loaded
	}
	auth := Authorities{
		Keygranting:    context.Authorities[AuthenticationAuthority].(*authorities.TLSAuthority),
		ServerTLS:      context.Authorities[ServerTLS].(*authorities.TLSAuthority),
		ClusterTLS:     context.Authorities["clustertls"].(*authorities.TLSAuthority),
		EtcdClient:     context.Authorities["etcd-client"].(*authorities.TLSAuthority),
		EtcdServer:     context.Authorities["etcd-server"].(*authorities.TLSAuthority),
		Kubernetes:     context.Authorities["kubernetes"].(*authorities.TLSAuthority),
		ServiceAccount: context.Authorities["serviceaccount"].(*authorities.StaticAuthority),
		SshHost:        context.Authorities["ssh-host"].(*authorities.SSHAuthority),
		SshUser:        context.Authorities["ssh-user"].(*authorities.SSHAuthority),
	}
	context.AuthenticationAuthority = auth.Keygranting
	context.ServerTLS = auth.ServerTLS
	groups := GenerateGroups(context)
	err = GenerateAccounts(context, conf, groups)
	if err != nil {
		return nil, err
	}
	err = GenerateGrants(context, conf, groups, auth)
	if err != nil {
		return nil, err
	}
	return context, nil
}
