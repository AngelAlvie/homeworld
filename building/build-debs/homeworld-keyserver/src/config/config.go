package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type ConfigAuthority struct {
	Name string
	Type string
	Key  string
	Cert string
}

type ConfigAccount struct {
	Principal         string
	Group             string
	LimitIP           bool
	DisableDirectAuth bool
	Metadata          map[string]string
}

type ConfigGrant struct {
	API          string
	Group        string
	Privilege    string
	Scope        string
	Authority    string
	IsHost       string
	Lifespan     string
	CommonName   string
	AllowedNames []string
	Contents     string
}

type ConfigGroup struct {
	Name    string
	Inherit string
}

type ConfigStatic string

type Config struct {
	AuthorityDir            string
	StaticDir               string
	AuthenticationAuthority string
	ServerTLS               string
	Authorities             []ConfigAuthority
	StaticFiles             []ConfigStatic
	Accounts                []ConfigAccount
	Groups                  []ConfigGroup
	Grants                  []ConfigGrant
}

func ParseConfigFromBytes(data []byte) (*Config, error) {
	config := new(Config)
	err := yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func LoadConfigFromBytes(data []byte) (*Context, error) {
	config, err := ParseConfigFromBytes(data)
	if err != nil {
		return nil, err
	}
	return config.Compile()
}

func LoadConfig(filename string) (*Context, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return LoadConfigFromBytes(contents)
}
