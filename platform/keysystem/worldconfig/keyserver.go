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
)

type Groups struct {
	KerberosAccounts *account.Group
	RootAdmins       *account.Group
	Nodes            *account.Group
	SupervisorNodes  *account.Group
	WorkerNodes      *account.Group
	MasterNodes      *account.Group
}

func GenerateGroups() Groups {
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

func GenerateAccounts(context *config.Context, conf *SpireSetup, groups Groups, auth Authorities) error {
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

		acc := &account.Account{
			Principal: principal,
			Group:     group,
			LimitIP:   limitIP,
			Metadata: map[string]string{
				"ip":       node.IP,
				"hostname": node.Hostname,
				"schedule": schedule,
				"kind":     node.Kind,
			},
		}
		accounts = append(accounts, acc)

		groups.Nodes.AllMembers = append(groups.Nodes.AllMembers, acc)
		group.AllMembers = append(group.AllMembers, acc)
	}

	// metrics principal used by homeworld-ssh-checker
	allAdmins := append([]string{"metrics@NONEXISTENT.REALM.INVALID"}, conf.RootAdmins...)

	for _, rootAdmin := range allAdmins {
		if rootAdmin == "" {
			return errors.New("cannot have an admin with an unnamed account")
		}
		// TODO: ensure that root admins are unique, including against the metrics admin
		acc := &account.Account{
			Principal:         rootAdmin,
			DisableDirectAuth: true,
			Group:             groups.RootAdmins,
		}
		accounts = append(accounts, acc)
		groups.RootAdmins.AllMembers = append(groups.RootAdmins.AllMembers, acc)
		groups.KerberosAccounts.AllMembers = append(groups.KerberosAccounts.AllMembers, acc)
	}

	if len(conf.RootAdmins) > 0 {
		for _, node := range conf.Nodes {
			if node.Kind == "supervisor" {
				principal := "host/" + node.Hostname + "." + conf.Cluster.ExternalDomain + "@" + conf.Cluster.KerberosRealm
				acc := &account.Account{
					Principal:         principal,
					DisableDirectAuth: true,
					Group:             groups.KerberosAccounts,
				}
				accounts = append(accounts, acc)
				groups.KerberosAccounts.AllMembers = append(groups.KerberosAccounts.AllMembers, acc)
			}
		}
	}

	for _, ac := range accounts {
		ac.Privileges = GrantsForAccount(context, conf, groups, auth, ac)
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

func GrantsForAccount(c *config.Context, conf *SpireSetup, groups Groups, auth Authorities, ac *account.Account) map[string]account.Privilege {
	// NOTE: at the point where this runs, not all accounts will necessarily be registered with the context!
	var grants = map[string]account.Privilege{}

	// ADMIN ACCESS TO THE RUNNING CLUSTER

	if groups.RootAdmins.HasMember(ac.Principal) {
		grants["access-ssh"] = account.NewSSHGrantPrivilege(
			auth.SshUser, false, 4*time.Hour,
			"temporary-ssh-grant-"+ac.Principal, []string{"root"},
		)
		grants["access-etcd"] = account.NewTLSGrantPrivilege(
			auth.EtcdClient, false, 4*time.Hour,
			"temporary-etcd-grant-"+ac.Principal, nil,
		)
		grants["access-kubernetes"] = account.NewTLSGrantPrivilege(
			auth.Kubernetes, false, 4*time.Hour,
			"temporary-kube-grant-"+ac.Principal, nil,
		)
	}

	// MEMBERSHIP IN THE CLUSTER
	if groups.RootAdmins.HasMember(ac.Principal) {
		grants["bootstrap"] = account.NewBootstrapPrivilege(
			groups.Nodes, time.Hour, c.TokenVerifier.Registry,
		)
	}

	if groups.SupervisorNodes.HasMember(ac.Principal) {
		if c.TokenVerifier.Registry == nil {
			panic("expected registry to exist")
		}
		grants["bootstrap-keyinit"] = account.NewBootstrapPrivilege(
			groups.Nodes, time.Hour, c.TokenVerifier.Registry,
		)
	}

	if groups.Nodes.HasMember(ac.Principal) {
		grants["renew-keygrant"] = account.NewTLSGrantPrivilege(auth.Keygranting, false, OneDay*40, ac.Principal, nil)
	}

	if groups.SupervisorNodes.HasMember(ac.Principal) {
		grants["auth-to-kerberos"] = account.NewImpersonatePrivilege(c.GetAccount, groups.KerberosAccounts)
	}

	// CONFIGURATION ENDPOINT

	if groups.Nodes.HasMember(ac.Principal) {
		hostname := ac.Metadata["hostname"]
		ip := ac.Metadata["ip"]
		schedule := ac.Metadata["schedule"]
		kind := ac.Metadata["kind"]
		grants["get-local-config"] = account.NewConfigurationPrivilege(
			`# generated automatically by keyserver
HOST_NODE=` + hostname + `
HOST_DNS=` + hostname + `.` + conf.Cluster.ExternalDomain + `
HOST_IP=` + ip + `
SCHEDULE_WORK=` + schedule + `
KIND=` + kind,
		)
	}

	// SERVER CERTIFICATES

	if groups.Nodes.HasMember(ac.Principal) {
		hostname := ac.Metadata["hostname"]
		ip := ac.Metadata["ip"]
		grants["grant-ssh-host"] = account.NewSSHGrantPrivilege(
			auth.SshHost, true, OneDay*60, "admitted-"+ac.Principal,
			[]string{
				hostname + "." + conf.Cluster.ExternalDomain,
				hostname,
				ip,
			},
		)
	}

	if groups.MasterNodes.HasMember(ac.Principal) {
		hostname := ac.Metadata["hostname"]
		ip := ac.Metadata["ip"]
		grants["grant-kubernetes-master"] = account.NewTLSGrantPrivilege(
			auth.Kubernetes, true, 30*OneDay, "kube-master-"+hostname,
			[]string{
				hostname + "." + conf.Cluster.ExternalDomain,
				hostname,
				"kubernetes",
				"kubernetes.default",
				"kubernetes.default.svc",
				"kubernetes.default.svc." + conf.Cluster.InternalDomain,
				ip,
				conf.Addresses.ServiceAPI,
			},
		)
		grants["grant-etcd-server"] = account.NewTLSGrantPrivilege(
			auth.EtcdServer, true, 30*OneDay, "etcd-server-"+hostname,
			[]string{
				hostname + "." + conf.Cluster.ExternalDomain,
				hostname,
				ip,
			},
		)
	}

	if groups.SupervisorNodes.HasMember(ac.Principal) {
		hostname := ac.Metadata["hostname"]
		grants["grant-registry-host"] = account.NewTLSGrantPrivilege(
			auth.ClusterTLS, true, 30*OneDay, "homeworld-supervisor-"+hostname,
			[]string{"homeworld.private"},
		)
	}

	// CLIENT CERTIFICATES

	if groups.Nodes.HasMember(ac.Principal) {
		hostname := ac.Metadata["hostname"]
		ip := ac.Metadata["ip"]
		grants["grant-kubernetes-worker"] = account.NewTLSGrantPrivilege(
			auth.Kubernetes, true, 30*OneDay, "kube-worker-"+hostname,
			[]string{
				hostname + "." + conf.Cluster.ExternalDomain,
				hostname,
				ip,
			},
		)
	}

	if groups.MasterNodes.HasMember(ac.Principal) {
		hostname := ac.Metadata["hostname"]
		ip := ac.Metadata["ip"]
		grants["grant-etcd-client"] = account.NewTLSGrantPrivilege(auth.EtcdClient, false, 30*OneDay, "etcd-client-"+hostname,
			[]string{
				hostname + "." + conf.Cluster.ExternalDomain,
				hostname,
				ip,
			},
		)
		grants["fetch-serviceaccount-key"] = account.NewFetchKeyPrivilege(auth.ServiceAccount)
	}

	return grants
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
	groups := GenerateGroups()
	err = GenerateAccounts(context, conf, groups, auth)
	if err != nil {
		return nil, err
	}
	return context, nil
}
