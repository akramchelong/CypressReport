package logger

import (
	"os"
	"strings"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
)

var (
	logger             loggable
	defaultLogLevel    int = infoLevel
	configuredLogLevel int = defaultLogLevel
	logLevels          map[int]string
)

const (
	debugLevel = iota
	infoLevel
	warningLevel
	errorLevel
	fatalLevel
	auditLevel
)

type loggable interface {
	logInLevel(level int, format string, a ...interface{})
}

func init() {
	logger = newLoggerBackend()

	logLevels = getLogLevels()
	configuredLogLevel = getConfiguredLogLevel()
}

// GetConfiguredLogLevel returns the configured log level as a string
func GetConfiguredLogLevel() string {
	return logLevels[configuredLogLevel]
}

func getLogLevels() map[int]string {
	logLevels = map[int]string{
		debugLevel:   "debug",
		infoLevel:    "info",
		warningLevel: "warning",
		errorLevel:   "error",
		fatalLevel:   "fatal",
		auditLevel:   "audit",
	}

	return logLevels
}

func getConfiguredLogLevel() int {
	envLogLevel := config.LogLevel
	for key, logLevel := range logLevels {
		if logLevel == strings.ToLower(envLogLevel) {
			return key
		}
	}

	return defaultLogLevel
}

// Debug outputs debug-level information.
//
// Debug-level is used for information that are useful when debugging an application.
func Debug(format string, a ...interface{}) {
	logger.logInLevel(debugLevel, format, a...)
}

// Info outputs info-level information.
//
// Info-level is used for interesting events.
// Example: Service starts up, user logs in, configuration assumptions.
func Info(format string, a ...interface{}) {
	logger.logInLevel(infoLevel, format, a...)
}

// Warning outputs warning-level information.
//
// Warning-level is used for exceptional occurrences that might be a problem,
// or might not.
// Example: Switching from primary to backup server, retrying an operation,
// poor use of an API, short loss of network- or database-connectivety.
func Warning(format string, a ...interface{}) {
	logger.logInLevel(warningLevel, format, a...)
}

// Error outputs error-level information.
//
// Error-levels is used for runtime errors that is fatal to the request and/or
// operation, but the service can limp along. These problems should be
// investigated.
// Example: Dropped database connection, can't access file.
func Error(format string, a ...interface{}) {
	logger.logInLevel(errorLevel, format, a...)
}

// Fatal outputs fatal-level information.
//
// Fatal-level is used for unrecoverable situations that is forcing the service
// to shutdown.
// Example: No more memory available
func Fatal(format string, a ...interface{}) {
	logger.logInLevel(fatalLevel, format, a...)
	os.Exit(1)
}

// Audit outputs audit information.
//
// Audit is used to track events on who did what when.
// Example: Client with id 8ded785d-b561-458e-9567-7aef439f63fe deleted by
// client 8ded785d-b561-458e-9567-7aef439f63fe
func Audit(format string, a ...interface{}) {
	logger.logInLevel(auditLevel, format, a...)
}
