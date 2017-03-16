package coyote

import (
	"context"
	"time"

	"path/filepath"

	"github.com/stugotech/coyote/acmelib"
	"github.com/stugotech/coyote/secret"
	"github.com/stugotech/coyote/store"
	"github.com/stugotech/golog"
	"golang.org/x/net/publicsuffix"
)

var logger = golog.NewPackageLogger()

const (
	authRetries = 5
	backoffMs   = 300
)

// Coyote describes the things that the coyote tool can do
type Coyote interface {
	// Authorize authorizes a domain under the users control.
	Authorize(domain string) error
	// BeginAuthorize fetches a challenge for the given domain.
	BeginAuthorize(domain string) (*acmelib.HTTPAuthChallenge, error)
	// CompleteAuthorize tells the ACME server to complete the challenge.
	CompleteAuthorize(challengeURI string) error
	// NewCertificate creates one or more certificates for the specified domains, grouped by registered domain.
	NewCertificate(domains []string) error
	// RenewExpiringCertificates checks expiry dates on certificates and renews certificates that will
	// expire before `before` has elapsed.
	RenewExpiringCertificates(before time.Duration) error
	// RenewLoop loops forever, checking expiry dates on certificates on the specified `period` and
	// renewing certificates that will expire before `before` has elapsed.
	RenewLoop(period time.Duration, before time.Duration) error
}

// Config describes the coyote configuration settings
type Config struct {
	Store        store.Store
	ContactEmail string
	DirectoyURI  string
	AcceptTOS    bool
	SecretKey    string
}

// coyote implements the Coyote interface
type coyote struct {
	config    *Config
	client    acmelib.Client
	secretBox secret.Box
}

// NewCoyote creates a new instance of the Coyote interface
func NewCoyote(config *Config) (Coyote, error) {
	secretBox, err := secret.NewBoxFromKeyString(config.SecretKey)
	if err != nil {
		return nil, logger.Errore(err)
	}

	c := &coyote{
		config:    config,
		secretBox: secretBox,
	}

	c.client, err = acmelib.NewClient(config.DirectoyURI)
	if err != nil {
		return nil, logger.Errore(err)
	}

	account, err := c.getAccount(config.ContactEmail)
	if err != nil {
		return nil, logger.Errore(err)
	}

	if account != nil {
		_, err = c.client.UseAccount(context.Background(), account)
		if err != nil {
			return nil, logger.Errore(err)
		}
	} else {
		// no account found - create new account
		account, err = c.createAccount(config.ContactEmail, config.AcceptTOS)
		if err != nil {
			return nil, logger.Errore(err)
		}
	}

	return c, nil
}

// getAccount looks up the account and returns the key if it exists
func (c *coyote) getAccount(email string) (*acmelib.Account, error) {
	account, err := c.config.Store.GetAccount(email)
	if err != nil {
		return nil, logger.Errore(err)
	}
	if account == nil {
		return nil, nil
	}
	key, err := c.secretBox.Open(account.Key)
	if err != nil {
		return nil, logger.Errore(err)
	}
	signer, err := parsePrivateKeyFromDER(key)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return &acmelib.Account{
		URI:   account.URI,
		Key:   signer,
		Email: account.Email,
	}, nil
}

// createAccount creates a new account
func (c *coyote) createAccount(email string, acceptTOS bool) (*acmelib.Account, error) {
	account, err := c.client.RegisterAccount(context.Background(), email, acceptTOS)
	if err != nil {
		return nil, logger.Errorex("error creating new account", err, golog.String("email", email))
	}
	// encrypt key
	keyBytes, err := c.secretBox.Seal(account.KeyBytes)
	if err != nil {
		return nil, logger.Errore(err)
	}
	// save new account
	storeAccount := &store.Account{
		URI:   account.URI,
		Email: email,
		Key:   keyBytes,
	}
	err = c.config.Store.PutAccount(storeAccount)
	if err != nil {
		return nil, logger.Errore(err)
	}
	return account, nil
}

// Authorize runs authorization on the given domain
func (c *coyote) Authorize(domain string) error {
	challenge, err := c.BeginAuthorize(domain)
	if err != nil {
		return logger.Errore(err)
	}

	ctx := context.Background()

	for i := 1; ; i++ {
		err = c.client.CompleteAuthorize(ctx, challenge.AuthChallenge)
		if err == nil {
			break
		}
		if i >= authRetries {
			return err
		}
		// wait a bit before trying again
		time.Sleep(time.Duration(i*backoffMs) * time.Millisecond)
	}

	logger.Info("authorization of domain successful", golog.String("domain", domain))
	return nil
}

// BeginAuthorize gets the challenge details for the given domain
func (c *coyote) BeginAuthorize(domain string) (*acmelib.HTTPAuthChallenge, error) {
	logger.Info("begin authorization of domain", golog.String("domain", domain))
	ctx := context.Background()

	challenge, err := c.client.BeginAuthorize(ctx, domain)
	if err != nil {
		return nil, logger.Errore(err)
	}

	if challenge == nil {
		logger.Debug("no authorization required", golog.String("domain", domain))
		return nil, nil
	}

	logger.Debug("challenge received",
		golog.String("URI", challenge.URI),
		golog.String("path", challenge.Path),
		golog.String("response", challenge.Response),
	)

	err = c.config.Store.PutChallenge(&store.Challenge{
		Key:   filepath.Base(challenge.Path),
		Value: challenge.Response,
	})

	if err != nil {
		return nil, logger.Errore(err)
	}

	return challenge, nil
}

// CompleteAuthorize waits until the challenge can be completed
func (c *coyote) CompleteAuthorize(challengeURI string) error {
	ctx := context.Background()

	err := c.client.CompleteAuthorizeURI(ctx, challengeURI)
	if err != nil {
		return logger.Errore(err)
	}

	logger.Info("authorization of domain successful")
	return nil
}

// NewCertificate creates a new certificate for the specified domains.
func (c *coyote) NewCertificate(domains []string) error {
	logger.Info("create new certificate",
		golog.Strings("domains", domains),
	)

	groupedDomains := make(map[string][]string)

	// authorize domains first and group under registered domains
	for _, d := range domains {
		if err := c.Authorize(d); err != nil {
			return logger.Errore(err)
		}
		reg, err := publicsuffix.EffectiveTLDPlusOne(d)
		if err != nil {
			return logger.Errorex("can't get public suffix for domain", err, golog.String("domain", d))
		}
		// don't add the domain itself to the child list
		if reg == d {
			_, ok := groupedDomains[reg]
			if !ok {
				groupedDomains[reg] = []string{}
			}
		} else {
			groupedDomains[reg] = append(groupedDomains[reg], d)
		}
	}

	// now create certificates
	for domain, sans := range groupedDomains {
		// see if the domain already has a certificate
		storeCert, err := c.config.Store.GetCertificate(domain)
		if err != nil {
			return logger.Errore(err)
		}

		if storeCert != nil {
			sans = uniqueStrings(sans, storeCert.AlternativeNames)
		}

		cert, err := c.client.CreateCertificate(context.Background(), domain, sans)
		if err != nil {
			return logger.Errore(err)
		}

		storeCert = &store.Certificate{
			Domain:           domain,
			AlternativeNames: sans,
			CertificateChain: cert.CertificatesPEM(),
			PrivateKey:       cert.PrivateKeyPEM(),
			Expires:          cert.Certificates[0].NotAfter,
		}

		err = c.config.Store.PutCertificate(storeCert)
		if err != nil {
			return logger.Errore(err)
		}
	}

	return nil
}

// RenewExpiringCertificates checks expiry dates on certificates and renews certificates that will
// expire before `before` has elapsed.
func (c *coyote) RenewExpiringCertificates(before time.Duration) error {
	certs, err := c.config.Store.GetCertificates()
	if err != nil {
		return logger.Errore(err)
	}

	threshold := time.Now().Add(before)

	for _, cert := range certs {
		if threshold.After(cert.Expires) {
			domains := append(cert.AlternativeNames[:], cert.Domain)
			if err = c.NewCertificate(domains); err != nil {
				return logger.Errore(err)
			}
		}
	}

	return nil
}

// RenewLoop loops forever, checking expiry dates on certificates on the specified `period` and
// renewing certificates that will expire before `before` has elapsed.
func (c *coyote) RenewLoop(period time.Duration, before time.Duration) error {
	for {
		if err := c.RenewExpiringCertificates(before); err != nil {
			return logger.Errore(err)
		}
		time.Sleep(period)
	}
}

// uniqueStrings returns the unique strings in all of the lists
func uniqueStrings(src ...[]string) []string {
	set := make(map[string]struct{})

	for _, srci := range src {
		for _, v := range srci {
			set[v] = struct{}{}
		}
	}

	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}

	return keys
}
