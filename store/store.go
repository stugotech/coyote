package store

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
	"github.com/docker/libkv/store/consul"
	"github.com/docker/libkv/store/etcd"
	"github.com/docker/libkv/store/zookeeper"
	"github.com/stugotech/goconfig"
	"github.com/stugotech/golog"
)

var logger = golog.NewPackageLogger()

// Configuration keys
const (
	StoreKey       = "store"
	StoreNodesKey  = "store-nodes"
	StorePrefixKey = "store-prefix"
)

// Store allows data to be retrieved from a data store
type Store interface {
	GetAccount(email string) (*Account, error)
	GetCertificate(domain string) (*Certificate, error)
	GetCertificates() ([]*Certificate, error)
	GetChallenge(key string) (*Challenge, error)

	PutAccount(account *Account) error
	PutCertificate(cert *Certificate) error
	PutChallenge(challenge *Challenge) error

	DeleteChallenge(key string) error
}

// Account represents a user account on an ACME directory
type Account struct {
	URI   string
	Email string
	Key   []byte
}

// Certificate represents a certificate used on a server
type Certificate struct {
	Domain           string
	AlternativeNames []string
	Expires          time.Time
	CertificateChain []byte
	PrivateKey       []byte
}

// Challenge represents an ACME challenge
type Challenge struct {
	Key   string
	Value string
}

// libkvStore implements the Store interface using Docker's libkv package
type libkvStore struct {
	store  store.Store
	prefix string
}

const (
	accountsPath     = "accounts"
	certificatesPath = "certificates"
	challengesPath   = "challenges"
)

// NewStoreFromConfig creates a new store based on the provided config
func NewStoreFromConfig(conf goconfig.Config) (Store, error) {
	return NewStore(
		conf.GetString(StoreKey),
		conf.GetStringSlice(StoreNodesKey),
		conf.GetString(StorePrefixKey),
	)
}

// NewStore creates a new store with the given parameters
func NewStore(storeName string, nodes []string, prefix string) (Store, error) {
	etcd.Register()
	consul.Register()
	boltdb.Register()
	zookeeper.Register()

	storeConfig := &store.Config{}
	s, err := libkv.NewStore(store.Backend(storeName), nodes, storeConfig)

	if err != nil {
		return nil, logger.Errore(err)
	}
	return NewLibKVStore(s, prefix)
}

// NewLibKVStore creates a Store using Docker's libkv package
func NewLibKVStore(store store.Store, prefix string) (Store, error) {
	return &libkvStore{
		store:  store,
		prefix: prefix,
	}, nil
}

// GetAccount gets the account for the specified email address
func (s *libkvStore) GetAccount(email string) (*Account, error) {
	kv, err := s.store.Get(s.path(accountsPath, email))
	if err == store.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, logger.Errore(err)
	}

	var account Account
	err = json.Unmarshal(kv.Value, &account)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return &account, nil
}

// GetCertificate gets the certificate for the specified subject domain
func (s *libkvStore) GetCertificate(domain string) (*Certificate, error) {
	kv, err := s.store.Get(s.path(certificatesPath, domain))
	if err == store.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, logger.Errore(err)
	}

	var cert Certificate
	err = json.Unmarshal(kv.Value, &cert)
	if err != nil {
		return nil, logger.Errore(err)
	}

	return &cert, nil
}

// GetCertificates gets all the certificates in the store
func (s *libkvStore) GetCertificates() ([]*Certificate, error) {
	kvs, err := s.store.List(s.path(certificatesPath))
	if err != nil {
		return nil, logger.Errore(err)
	}

	var certs []*Certificate

	for _, kv := range kvs {
		var cert Certificate

		err = json.Unmarshal(kv.Value, &cert)
		if err != nil {
			return nil, logger.Errore(err)
		}

		certs = append(certs, &cert)
	}

	return certs, nil
}

// GetChallenge gets a challenge from the store
func (s *libkvStore) GetChallenge(key string) (*Challenge, error) {
	kv, err := s.store.Get(s.path(challengesPath, key))
	if err == store.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, logger.Errorex("error retrieving challenge", err)
	}
	return &Challenge{
		Key:   key,
		Value: string(kv.Value),
	}, nil
}

// PutAccount saves an account in the store
func (s *libkvStore) PutAccount(account *Account) error {
	if account.Email == "" {
		return logger.Error("must specify email for account")
	}
	if account.URI == "" {
		return logger.Error("must specify URI for account")
	}
	if len(account.Key) == 0 {
		return logger.Error("must specify key for account")
	}
	bytes, err := json.Marshal(account)
	if err != nil {
		return logger.Errore(err)
	}

	err = s.store.Put(s.path(accountsPath, account.Email), bytes, nil)
	if err != nil {
		return logger.Errore(err)
	}

	return nil
}

// PutCertificate saves a certificate in the store
func (s *libkvStore) PutCertificate(cert *Certificate) error {
	bytes, err := json.Marshal(cert)
	if err != nil {
		return logger.Errore(err)
	}

	err = s.store.Put(s.path(certificatesPath, cert.Domain), bytes, nil)
	if err != nil {
		return logger.Errore(err)
	}

	return nil
}

// PutChallenge saves a challenge in the store
func (s *libkvStore) PutChallenge(challenge *Challenge) error {
	logger.Debug("saving challenge in store",
		golog.String("key", challenge.Key),
		golog.String("value", challenge.Value),
	)

	if challenge.Key == "" {
		return logger.Error("must specify key for challenge")
	}
	if challenge.Value == "" {
		return logger.Error("must specify value for challenge")
	}
	err := s.store.Put(s.path(challengesPath, challenge.Key), []byte(challenge.Value), nil)
	if err != nil {
		return logger.Errorex("error saving challenge in store", err)
	}
	return nil
}

// DeleteChallenge deletes a challenge from the store
func (s *libkvStore) DeleteChallenge(key string) error {
	logger.Debug("trying to remove challenge from store", golog.String("key", key))

	if key == "" {
		return logger.Error("must specify key")
	}

	err := s.store.Delete(key)
	if err != nil {
		return logger.Errorex("error while trying to remove challenge from store", err, golog.String("key", key))
	}

	return nil
}

// path constructs a path from the given components
func (s *libkvStore) path(components ...string) string {
	components = append([]string{s.prefix}, components...)
	return filepath.Join(components...)
}
