// +build !windows

package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type loggerBackend struct {
	mainLogger *log.Logger
	errLogger  *log.Logger
}

func newLoggerBackend() loggable {
	mainLogger := log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errLogger := log.New(os.Stderr, "", log.Ldate|log.Ltime)

	return &loggerBackend{mainLogger, errLogger}
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

	if level > warningLevel {
		l.errLogger.Printf("%s: %s", strings.ToUpper(prefix), msg)
		return
	}

	l.mainLogger.Printf("%s: %s", strings.ToUpper(prefix), msg)
}
