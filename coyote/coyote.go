package coyote

import (
	"context"
	"time"

	"path/filepath"

	"github.com/stugotech/coyote/acmelib"
	"github.com/stugotech/coyote/secret"
	"github.com/stugotech/coyote/store"
	"github.com/stugotech/golog"
)

var logger = golog.NewPackageLogger()

// Coyote describes the things that the coyote tool can do
type Coyote interface {
	// Authorize authorizes a domain under the users control.
	Authorize(domain string) error
	// BeginAuthorize fetches a challenge for the given domain.
	BeginAuthorize(domain string) (*acmelib.HTTPAuthChallenge, error)
	// CompleteAuthorize tells the ACME server to complete the challenge.
	CompleteAuthorize(challengeURI string) error
	// NewCertificate creates a new certificate for the specified domain.
	NewCertificate(domain string, sans []string) error
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
	storeAccount := &Account{
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
	err = c.client.CompleteAuthorize(ctx, challenge.AuthChallenge)
	if err != nil {
		return logger.Errore(err)
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

	err = c.config.Store.PutChallenge(&Challenge{
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

// NewCertificate creates a new certificate for the specified domain.
func (c *coyote) NewCertificate(domain string, sans []string) error {
	ctx := context.Background()
	cert, err := c.client.CreateCertificate(ctx, domain, sans)
	if err != nil {
		return logger.Errore(err)
	}

	storeCert := &Certificate{
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
			if err = c.NewCertificate(cert.Domain, cert.AlternativeNames); err != nil {
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
