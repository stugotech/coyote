package vulcand

import (
	"github.com/stugotech/coyote/sync"
	"github.com/stugotech/golog"
	"github.com/vulcand/vulcand/api"
	"github.com/vulcand/vulcand/engine"
	"github.com/vulcand/vulcand/plugin"
)

var logger = golog.NewPackageLogger()

// client is an implementation of the Client interface
type client struct {
	client *api.Client
}

// NewClient creates a new connection to the vulcand API
func NewClient(address string) sync.Client {
	return &client{
		client: api.NewClient(address, plugin.NewRegistry()),
	}
}

// GetHosts returns all hosts
func (c *client) GetHosts() ([]*sync.Host, error) {
	apiHosts, err := c.client.GetHosts()
	if err != nil {
		return nil, logger.Errore(err)
	}

	var hosts []*sync.Host
	for _, h := range apiHosts {
		hosts = append(hosts, &sync.Host{
			Domain:         h.Name,
			CertificatePEM: string(h.Settings.KeyPair.Cert),
			PrivateKeyPEM:  string(h.Settings.KeyPair.Key),
		})
	}

	return hosts, nil
}

// GetHost returns a single host
func (c *client) GetHost(domain string) (*sync.Host, error) {
	host, err := c.client.GetHost(engine.HostKey{Name: domain})
	if err != nil {
		return nil, logger.Errore(err)
	}
	if host == nil {
		return nil, nil
	}

	return &sync.Host{
		Domain:         host.Name,
		CertificatePEM: string(host.Settings.KeyPair.Cert),
		PrivateKeyPEM:  string(host.Settings.KeyPair.Key),
	}, nil
}

// PutHost upserts a host
func (c *client) PutHost(host *sync.Host) error {
	apiHost := engine.Host{
		Name: host.Domain,
		Settings: engine.HostSettings{
			KeyPair: &engine.KeyPair{
				Cert: []byte(host.CertificatePEM),
				Key:  []byte(host.PrivateKeyPEM),
			},
		},
	}
	if err := c.client.UpsertHost(apiHost); err != nil {
		return logger.Errorex("failed to upsert host", err)
	}
	return nil
}
