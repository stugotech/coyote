package sync

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/stugotech/coyote/coyote"
	"github.com/stugotech/coyote/cryptutil"
	"github.com/stugotech/coyote/store"
	"github.com/stugotech/golog"
)

var logger = golog.NewPackageLogger()

// Client represents the interface to the sync API.
type Client interface {
	GetHosts() ([]*Host, error)
	GetHost(domain string) (*Host, error)
	PutHost(host *Host) error
}

// Host represents a host in the synced system.
type Host struct {
	Domain         string
	CertificatePEM string
	PrivateKeyPEM  string
}

// DecodeCertificates returns the decoded certificate
func (h *Host) DecodeCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	// decode the whole bundle
	for data := []byte(h.CertificatePEM); ; {
		var block *pem.Block
		block, data = pem.Decode(data)

		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return []*x509.Certificate{}, logger.Errorex("error decoding certificate", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return []*x509.Certificate{}, logger.Error("no certificate data found")
	}
	return certs, nil
}

// ExternalWithCoyote copies all certificate keys to the external system
func ExternalWithCoyote(coy coyote.Coyote, external Client) error {
	certs, err := coy.GetCertificates()
	if err != nil {
		return logger.Errore(err)
	}
	return Certificates(certs, external)
}

// Certificate pushes the keys for a single certificate to all relevant remote hosts.
func Certificate(cert *store.Certificate, external Client) error {
	for _, domain := range getAllNames(cert) {
		logger.Debug("syncing certificate with external system",
			golog.String("domain", domain),
			golog.String("thumbprint", cert.Thumbprint),
		)

		host, err := external.GetHost(domain)
		if err != nil {
			return logger.Errore(err)
		}

		if host != nil {
			bundle, err := host.DecodeCertificates()
			if err != nil {
				return logger.Errore(err)
			}

			extThumbprint := cryptutil.Thumbprint(bundle[0].Raw)

			logger.Debug("found certificate in external store",
				golog.String("thumbprint", extThumbprint),
			)

			if extThumbprint == cert.Thumbprint {
				return nil
			}
		}
		host = &Host{
			Domain:         domain,
			CertificatePEM: string(cert.CertificateChain),
			PrivateKeyPEM:  string(cert.PrivateKey),
		}

		if err := external.PutHost(host); err != nil {
			return logger.Errore(err)
		}
	}
	return nil
}

// Certificates pushes the keys for a specified certificates to all relevant remote hosts.
func Certificates(certs []*store.Certificate, external Client) error {
	for _, cert := range certs {
		if err := Certificate(cert, external); err != nil {
			return logger.Errore(err)
		}
	}
	return nil
}

func getAllNames(cert *store.Certificate) []string {
	names := []string{cert.Domain}
	return append(names, cert.AlternativeNames...)
}
