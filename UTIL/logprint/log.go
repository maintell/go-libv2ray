package logprint

func Debugf(msg string, args ...interface{}) {
	logger.Debugf(msg, args...)
}

func Infof(msg string, args ...interface{}) {
	logger.Infof(msg, args...)
}

func Warnf(msg string, args ...interface{}) {
	logger.Warnf(msg, args...)
}

func Errorf(msg string, args ...interface{}) {
	logger.Errorf(msg, args...)
}

func Fatalf(msg string, args ...interface{}) {
	logger.Fatalf(msg, args...)
}
