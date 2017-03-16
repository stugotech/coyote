package server

import (
	"fmt"

	"net/http"

	"regexp"
	"strings"

	"github.com/stugotech/coyote/store"
	"github.com/stugotech/goconfig"
	"github.com/stugotech/golog"
)

const (
	pathRegexp = "^/%s/([a-zA-Z0-9_-]+)$"
)

// The following consts define config keys for this module
const (
	ListenKey         = "listen"
	PathPrefixKey     = "path-prefix"
	PathPrefixDefault = ".well-known/acme-challenge"
)

// Config describes the configuration settings for the server
type Config struct {
	Store       string
	StoreNodes  []string
	StorePrefix string
}

type serverInfo struct {
	config    *Config
	store     store.Store
	validPath *regexp.Regexp
	listen    string
}

type serverInfoHandler func(s *serverInfo, response http.ResponseWriter, request *http.Request)

// Server describes an ACME challenge server
type Server interface {
	Listen() error
}

var logger = golog.NewPackageLogger()

// NewServerFromConfig creates a new server from the config specified in the provider
func NewServerFromConfig(config goconfig.Config) (Server, error) {
	st, err := store.NewStoreFromConfig(config)
	if err != nil {
		return nil, logger.Errore(err)
	}
	return NewServer(st, config.GetString(ListenKey), config.GetString(PathPrefixKey))
}

// NewServer creates a new server
func NewServer(st store.Store, listen string, pathPrefix string) (Server, error) {
	logger.Info("creating new server",
		golog.String("listen", listen),
		golog.String("path-prefix", pathPrefix),
	)

	pathPrefix = strings.Trim(pathPrefix, "/")
	validPath := regexp.MustCompile(fmt.Sprintf(pathRegexp, pathPrefix))

	return &serverInfo{
		store:     st,
		validPath: validPath,
		listen:    listen,
	}, nil
}

// Listen starts the server listening for connections
func (s *serverInfo) Listen() error {
	http.HandleFunc("/", s.makeHandler(challengeHandler))
	logger.Info("server listening", golog.String("interface", s.listen))
	err := http.ListenAndServe(s.listen, nil)

	if err != nil {
		return logger.Errore(err)
	}

	return nil
}

func challengeHandler(s *serverInfo, response http.ResponseWriter, request *http.Request) {
	match := s.validPath.FindStringSubmatch(request.URL.Path)
	if match == nil {
		logger.Error("invalid URL format", golog.String("path", request.URL.Path))
		http.NotFound(response, request)
		return
	}

	key := match[1]
	challenge, err := s.store.GetChallenge(key)

	if err != nil {
		logger.Error("error getting value", golog.String("url", request.URL.Path), golog.String("key", key))
		logger.Errore(err)
		http.NotFound(response, request)
		return
	}

	response.Write([]byte(challenge.Value))

	if err = s.store.DeleteChallenge(key); err != nil {
		logger.Error("error deleting key", golog.String("key", key))
		logger.Errore(err)
	}
}

func (s *serverInfo) makeHandler(fn serverInfoHandler) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		fn(s, response, request)
	}
}
