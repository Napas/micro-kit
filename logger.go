package micro_kit

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"path"
	"runtime"
	"runtime/debug"
)

type callInfo struct {
	packageName string
	fileName    string
	funcName    string
	line        int
}

type ContextHook struct{}

func (hook ContextHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (hook *ContextHook) Fire(entry *logrus.Entry) error {
	if pc, file, line, ok := runtime.Caller(10); ok {
		funcName := runtime.FuncForPC(pc).Name()

		entry.Data["source"] = fmt.Sprintf("%s:%v:%s", path.Base(file), line, path.Base(funcName))

		if entry.Level == logrus.DebugLevel {
			entry.Data["stackTrace"] = debug.Stack()
		}
	}

	return nil
}
