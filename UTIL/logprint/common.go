package logprint

import (
	"github.com/eycorsican/go-tun2socks/common/log"
)

var logger *log.Logger

const (
	tag   = "logprint"
	level = "info"
)

func SetLogLogger(tag string, logLevel string) {
	SetLogTag(tag)
	SetLogLevel(logLevel)
	log.Infof("LogLevel: %s", GetLogLevel())
}

func SetLogTag(tag string) {
	logger.SetLogTag(tag)
}

func SetLogLevel(logLevel string) {
	logger.SetLogLevel(logLevel)
	log.SetLogLevel(logLevel)
}

func GetLogTag() string {
	return logger.GetLogTag()
}

func GetLogLevel() string {
	return logger.GetLogLevel()
}

func init() {
	logger = log.NewLogger(tag, level)
}
