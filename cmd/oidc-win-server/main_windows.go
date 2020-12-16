// +build windows

package main

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/oauth2"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/validator"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/net/limit"

	"golang.org/x/crypto/pkcs12"
	"golang.org/x/sys/windows/registry"
)

// build variables
var (
	commit  string
	builtAt string
	svcName string
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Environment variables are used for configuration and the following are supported:")
		fmt.Fprintln(flag.CommandLine.Output(), config.GetHelpText())
	}
	flag.Parse()
}

func main() {
	logger.Info("Using configuration " + config.GetConfigured(logger.GetConfiguredLogLevel()))
	logger.Info("%v", os.Args)
	defer logger.Close()

	logger.Info("Init database")
	db := database.NewDatabase()

	logger.Info("Init loginhandler")
	loginHandler := auth.LoginHandler{}

	exePath, _ := os.Executable()
	currentDir := filepath.Dir(exePath)
	validator := validator.New()
	server, err := oauth2.NewServer(loginHandler, db, currentDir, validator)
	if err != nil {
		logger.Error("Init server failed: %v", err)
		os.Exit(1)
	}

	limitConfig := limit.Config{
		BucketSize:          5,
		RefillRate:          1,
		CleanupInterval:     3 * time.Minute,
		VisitorOldTimeLimit: 5 * time.Minute,
	}
	logger.Info("Rate limit config: %+v", limitConfig)
	limiter := limit.NewLimiter(limitConfig)

	router := oauth2.NewRouter(server, limiter)

	certPath, err := getCertPath()
	if err != nil {
		logger.Fatal("Could not get certificate path from registry. Error: %s", err.Error())
	}
	logger.Debug("Cert path is %q", certPath)
	cert, err := readPFXCertificate(certPath)
	if err != nil {
		// Fatal since we don't want to continue without the HTTPS cert
		logger.Fatal(err.Error())
	}

	bindAddr := fmt.Sprintf(":%d", config.Port)
	httpServer := http.Server{
		Addr:    bindAddr,
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
		},
	}

	logger.Info("Starting server (version: %q, built at: %q).", commit, builtAt)
	err = httpServer.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("Error starting server. %s", err.Error())
	}
}

// getCertPath reads the certificate path for this plugin from the registry.
// The registry key is set by the ACS server.
func getCertPath() (string, error) {
	// The certificate file path is written to the registry: HKLM\Software\Axis
	// Communications\Axis Camera Station Server\Plugins\<pluginIdFromMetadata>\CertificatePath
	registryPath := fmt.Sprintf("SOFTWARE\\Axis Communications\\Axis Camera Station Server\\Plugins\\%s", svcName)
	logger.Debug("Looking for cert in registry %q", registryPath)

	// registry.LOCAL_MACHINE -> Use 'HKEY_LOCAL_MACHINE' as the base for the registry path.
	// registry.QUERY_VALUE -> Required to query the values of a registry key.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, registryPath, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	path, _, err := k.GetStringValue("CertificatePath")
	if err != nil {
		return "", err
	}

	return path, nil
}

// readPFXCertificate reads a pfx certificate from specified path and returns a
// tls.Certificate and potential errors if any.
func readPFXCertificate(certPath string) (certificate *tls.Certificate, err error) {
	logger.Debug("Attempting to read cert from %s", certPath)
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		logger.Debug(err.Error())
		return nil, fmt.Errorf("Could not read cert %q. Error: %s", certPath, err.Error())
	}

	blocks, err := pkcs12.ToPEM(certData, "")
	if err != nil {
		logger.Debug(err.Error())
		return nil, err
	}

	if len(blocks) != 2 {
		return nil, fmt.Errorf("Expected 2 blocks, got %d.", len(blocks))
	}

	var privKeyPEMBlock []byte
	var certPEMBlock []byte
	for _, b := range blocks {
		if b.Type == "CERTIFICATE" {
			certPEMBlock = append(certPEMBlock, pem.EncodeToMemory(b)...)
		} else if b.Type == "PRIVATE KEY" {
			privKeyPEMBlock = append(privKeyPEMBlock, pem.EncodeToMemory(b)...)
		}
	}

	if len(privKeyPEMBlock) == 0 || len(certPEMBlock) == 0 {
		return nil, errors.New("Expected cert and private key in PEM block.")
	}

	cert, err := tls.X509KeyPair(certPEMBlock, privKeyPEMBlock)
	if err != nil {
		logger.Debug(err.Error())
		return nil, err
	}

	return &cert, nil
}
