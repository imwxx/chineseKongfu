package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger

func init() {
	Logger = logrus.New()
	Logger.Formatter = &logrus.JSONFormatter{}
	Logger.Level = logrus.InfoLevel
	Logger.Out = os.Stderr
}
