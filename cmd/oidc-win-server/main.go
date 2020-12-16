// +build !windows

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/oauth2"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/validator"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/net/limit"
)

// build variables
var (
	commit  string
	builtAt string
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
	logger.Info("Starting server (version: %q, built at: %q).", commit, builtAt)

	db := database.NewDatabase()
	loginHandler := auth.LoginHandler{}

	exePath, _ := os.Executable()
	currentDir := filepath.Dir(exePath)
	validator := validator.New()
	server, err := oauth2.NewServer(loginHandler, db, currentDir, validator)
	if err != nil {
		logger.Error(err.Error())
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

	ipAddress := "127.0.0.1"
	cert, err := util.GenerateSelfSignedCertificate(ipAddress)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	bindAddr := fmt.Sprintf("%s:%d", ipAddress, config.Port)
	httpServer := http.Server{
		Addr:    bindAddr,
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
		},
	}
	logger.Info("Server started on %s.\n", bindAddr)
	err = httpServer.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal(err.Error())
	}
}
