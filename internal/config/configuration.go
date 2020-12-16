package config

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"text/template"
	"time"
)

type intConfiguration struct {
	EnvVariable  string
	DefaultValue int64
	MinValue     int64
	MaxValue     int64
}

type stringConfiguration struct {
	EnvVariable  string
	DefaultValue string
}

var (
	// LogLevel string
	LogLevel string

	// Port int
	Port int64

	// MaxContentLength int
	MaxContentLength int64

	// RefreshTokenTimeout time.Duration hours
	RefreshTokenTimeout time.Duration

	// RefreshTokenMaxLifetime time.Duration hours
	RefreshTokenMaxLifetime time.Duration

	// AccessTokenExpiry time.Duration minutes
	AccessTokenExpiry time.Duration

	// AuthSessionExpiry time.Duration minutes
	AuthSessionExpiry time.Duration

	// CodeExchangeExpiry time.Duration minutes
	CodeExchangeExpiry time.Duration

	logLevel = stringConfiguration{
		EnvVariable:  "LOG_LEVEL",
		DefaultValue: "info",
	}
	port = intConfiguration{
		EnvVariable:  "PORT",
		DefaultValue: 50120,
		MinValue:     0,
		MaxValue:     65535,
	}
	maxContentLength = intConfiguration{
		EnvVariable:  "MAX_CONTENT_LENGTH",
		DefaultValue: 102400,
		MinValue:     10,
		MaxValue:     2147483648,
	}
	refreshTokenTimeout = intConfiguration{
		EnvVariable:  "REFRESH_TOKEN_TIMEOUT",
		DefaultValue: 12,
		MinValue:     0,
		MaxValue:     30 * 24,
	}
	refreshTokenMaxLifetime = intConfiguration{
		EnvVariable:  "REFRESH_TOKEN_MAX_LIFETIME",
		DefaultValue: 30 * 24,
		MinValue:     0,
		MaxValue:     2 * 365 * 24,
	}
	accessTokenExpiry = intConfiguration{
		EnvVariable:  "ACCESS_TOKEN_EXPIRY",
		DefaultValue: 15,
		MinValue:     0,
		MaxValue:     60,
	}
	authSessionExpiry = intConfiguration{
		EnvVariable:  "AUTH_SESSION_EXPIRY",
		DefaultValue: 20,
		MinValue:     0,
		MaxValue:     60,
	}
	codeExchangeExpiry = intConfiguration{
		EnvVariable:  "CODE_EXCHANGE_EXPIRY",
		DefaultValue: 1,
		MinValue:     0,
		MaxValue:     30,
	}
)

// Initialize all parameters configurable through Environment variables.
func init() {
	LogLevel = parseStringConfig(logLevel)
	Port = parseNumberConfig(port)
	MaxContentLength = parseNumberConfig(maxContentLength)
	RefreshTokenTimeout = parseHourConfig(refreshTokenTimeout)
	RefreshTokenMaxLifetime = parseHourConfig(refreshTokenMaxLifetime)
	AccessTokenExpiry = parseMinuteConfig(accessTokenExpiry)
	AuthSessionExpiry = parseMinuteConfig(authSessionExpiry)
	CodeExchangeExpiry = parseMinuteConfig(codeExchangeExpiry)
}

// GetConfigured returns a pretty-printed string of the configured values.
// Log level has to be provided from the logger since that is where the
// validation is performed.
func GetConfigured(configuredLogLevel string) string {
	templateText := `
	Log level:                   {{.configuredLogLevel}}
	Port:                        {{.Port}}
	Max content-length:          {{.MaxContentLength}}B
	Access token expiry time:    {{.AccessTokenExpiry}}
	Refresh token timeout:       {{.RefreshTokenTimeout}}
	Refresh token max lifetime:  {{.RefreshTokenMaxLifetime}}
	Auth session expiry time:    {{.AuthSessionExpiry}}
	Code exchange expiry time:   {{.CodeExchangeExpiry}}
`
	data := map[string]interface{}{
		"configuredLogLevel":      configuredLogLevel,
		"Port":                    Port,
		"MaxContentLength":        MaxContentLength,
		"AccessTokenExpiry":       AccessTokenExpiry,
		"RefreshTokenTimeout":     RefreshTokenTimeout,
		"RefreshTokenMaxLifetime": RefreshTokenMaxLifetime,
		"AuthSessionExpiry":       AuthSessionExpiry,
		"CodeExchangeExpiry":      CodeExchangeExpiry,
	}
	return templateToString(templateText, data)
}

// GetHelpText returns a pretty-printed string containing informative
// descriptions of available configuration
func GetHelpText() string {
	templateText := `
{{.logLevel.EnvVariable}} - string
	Configure the desired log level. This configuration sets the level of
	which logs to ignore. Logging made with a lower level than configured
	will not be printed.
	[debug, info, warning, error, fatal]
	(default {{.logLevel.DefaultValue}})
{{.port.EnvVariable}} - number
	Configure the desired port. This configuration sets the port that the
	HTTP server shall listen to.
	(default {{.port.DefaultValue}})
{{.maxContentLength.EnvVariable}} - number
	Configure the desired max content-length. This configuration sets the
	maximum allowed content-length in bytes for HTTP requests. Requests made
	with a content-length higher than this value will receive a 400 Bad
	Request.
	(default {{.maxContentLength.DefaultValue}})
{{.accessTokenExpiry.EnvVariable}} - number
	Configure the desired lifespan of access tokens. This configuration sets
	the expiry time in minutes for all oauth access tokens.
	(default {{.accessTokenExpiry.DefaultValue}})
	(max {{.accessTokenExpiry.MaxValue}})
{{.refreshTokenTimeout.EnvVariable}} - number
	Configure the desired refresh token timeout. This configuration sets the
	limit for how long a refresh token can be inactive in hours before it is
	destroyed and cannot be used for refreshing access tokens.
	(default {{.refreshTokenTimeout.DefaultValue}})
	(max {{.refreshTokenTimeout.MaxValue}})
{{.refreshTokenMaxLifetime.EnvVariable}} - number
	Configure the desired maximum lifespan of refresh tokens. This
	configuration sets the expiry time in hours for all oauth refresh tokens.
	(default {{.refreshTokenMaxLifetime.DefaultValue}})
	(max {{.refreshTokenMaxLifetime.MaxValue}})
{{.authSessionExpiry.EnvVariable}} - number
	Configure the desired lifespan of authentication sessions. This
	configuration sets the timeout in minutes for all login attempts. Login
	forms idle longer than this will return a 400 Bad Request when submitted.
	(default {{.authSessionExpiry.DefaultValue}})
	(max {{.authSessionExpiry.MaxValue}})
{{.codeExchangeExpiry.EnvVariable}} - number
	Configure the desired lifespan of code exchange sessions. This
	configuration sets the timeout in minutes for all code exchange attempts.
	Code exchanges performed after this will receive a 400 Bad Request.
	(default {{.codeExchangeExpiry.DefaultValue}})
	(max {{.codeExchangeExpiry.MaxValue}})
`

	data := map[string]interface{}{
		"logLevel":                logLevel,
		"port":                    port,
		"maxContentLength":        maxContentLength,
		"accessTokenExpiry":       accessTokenExpiry,
		"refreshTokenTimeout":     refreshTokenTimeout,
		"refreshTokenMaxLifetime": refreshTokenMaxLifetime,
		"authSessionExpiry":       authSessionExpiry,
		"codeExchangeExpiry":      codeExchangeExpiry,
	}

	return templateToString(templateText, data)
}

func parseStringConfig(conf stringConfiguration) string {
	return os.Getenv(conf.EnvVariable)
}

func parseNumberConfig(conf intConfiguration) int64 {
	value := confToInt64(conf)
	return value
}

func parseMinuteConfig(conf intConfiguration) time.Duration {
	value := confToInt64(conf)
	return time.Duration(value) * time.Minute
}

func parseHourConfig(conf intConfiguration) time.Duration {
	value := confToInt64(conf)
	return time.Duration(value) * time.Hour
}

func confToInt64(conf intConfiguration) int64 {
	env, exist := os.LookupEnv(conf.EnvVariable)
	if !exist {
		return conf.DefaultValue
	}
	value, err := strconv.ParseInt(env, 10, 64)
	if err != nil {
		fmt.Printf("Invalid format for variable %q, defaulting to %d\n", conf.EnvVariable, conf.DefaultValue)
		return conf.DefaultValue
	}
	if value < conf.MinValue {
		fmt.Printf("Variable %q below minimum %d, defaulting to %d\n", conf.EnvVariable, conf.MinValue, conf.MinValue)
		return conf.MinValue
	}
	if value > conf.MaxValue {
		fmt.Printf("Variable %q above maximum %d, defaulting to %d\n", conf.EnvVariable, conf.MaxValue, conf.MaxValue)
		return conf.MaxValue
	}
	return value
}

func templateToString(templateText string, data interface{}) string {
	t, err := template.New("").Parse(templateText)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		panic("Invalid templating")
	}
	out := new(bytes.Buffer)
	err = t.Execute(out, data)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		panic("Invalid templating")
	}
	return out.String()
}
