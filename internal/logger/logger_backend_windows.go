// +build windows

package logger

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

var (
	eventid uint32 = 10001
	elog    *eventlog.Log
)

type loggerBackend struct {
}

func newLoggerBackend() loggable {
	const svcName = "OIDC-IAM"
	elog, _ = eventlog.Open(svcName)

	return &loggerBackend{}
}

func Close() error {
	return elog.Close()
}

// logInLevel outputs the log if the level is >= the configured logLevel.
func (l loggerBackend) logInLevel(level int, format string, a ...interface{}) {
	if level < configuredLogLevel {
		return
	}

	prefix, ok := logLevels[level]
	if !ok {
		panic(fmt.Sprintf("No error level %v exists. \n", level))
	}
	msg := fmt.Sprintf(format, a...)

	if level >= errorLevel {
		_ = elog.Error(eventid, fmt.Sprintf("%s: %s", strings.ToUpper(prefix), msg))
		return
	}
	if level >= warningLevel {
		_ = elog.Warning(eventid, fmt.Sprintf("%s: %s", strings.ToUpper(prefix), msg))
		return
	}
	_ = elog.Info(eventid, fmt.Sprintf("%s: %s", strings.ToUpper(prefix), msg))
}
