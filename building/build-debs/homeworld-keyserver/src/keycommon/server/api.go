package server

import (
	"crypto/x509"
	"fmt"
	"util/wraputil"
	"keycommon/endpoint"
)

type Keyserver struct {
	endpoint endpoint.ServerEndpoint
}

func NewKeyserver(authority []byte, hostname string) (*Keyserver, error) {
	cert, err := wraputil.LoadX509CertFromPEM(authority)
	if err != nil {
		return nil, fmt.Errorf("While parsing authority certificate: %s", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	ep, err := endpoint.NewServerEndpoint("https://" + hostname + ":20557/", pool)
	if err != nil {
		return nil, err // should not happen -- the URL provided also satisfies the checked constraints
	}
	return &Keyserver{endpoint: ep}, nil
}

func (k *Keyserver) GetStatic(staticname string) ([]byte, error) {
	if staticname == "" {
		return nil, fmt.Errorf("Static filename is empty.")
	}
	return k.endpoint.Get("/static/" + staticname)
}

func (k *Keyserver) GetPubkey(authorityname string) ([]byte, error) {
	if authorityname == "" {
		return nil, fmt.Errorf("Authority name is empty.")
	}
	return k.endpoint.Get("/pub/" + authorityname)
}
