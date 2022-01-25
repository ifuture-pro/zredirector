package config

import (
	"fmt"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	"os"
	"path"
	"strings"
	"time"
)

const LogPath = "./logs"
const FileSuffix = ".log"

func InitLog() *logrus.Logger {
	Logger := logrus.New()

	//Logger.Out = os.Stdout
	//file, err := os.OpenFile("z.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	//if err == nil {
	//	Logger.Out = file
	//} else {
	//	Logger.Warn("Failed to log to file, using default stdout")
	//}
	//mw := io.MultiWriter(os.Stdout, src)
	//Logger.SetOutput(mw)
	//Logger.SetFormatter(&logrus.JSONFormatter{})
	//Logger.WithFields(logrus.Fields{
	//	"pid": os.Getpid(),
	//})
	//Logger.SetLevel(logrus.DebugLevel)
	//Logger.SetReportCaller(true)

	Logger.Out = os.Stdout

	Logger.SetLevel(logrus.TraceLevel)

	NewSimpleLogger(Logger, LogPath, 15)
	return Logger
}

/**
  文件日志
*/
func NewSimpleLogger(log *logrus.Logger, logPath string, save uint) {

	lfHook := lfshook.NewHook(lfshook.WriterMap{
		logrus.DebugLevel: writer(logPath, "debug", save), // 为不同级别设置不同的输出目的
		logrus.InfoLevel:  writer(logPath, "info", save),
		logrus.WarnLevel:  writer(logPath, "warn", save),
		logrus.ErrorLevel: writer(logPath, "error", save),
		logrus.FatalLevel: writer(logPath, "fatal", save),
		logrus.PanicLevel: writer(logPath, "panic", save),
	}, &logrus.TextFormatter{FullTimestamp: true})

	log.AddHook(lfHook)
}

/**
文件设置
*/
func writer(logPath string, level string, save uint) *rotatelogs.RotateLogs {
	logFullPath := path.Join(logPath, level)
	//var cstSh, _ = time.LoadLocation("Asia/Shanghai") //上海
	//fileSuffix := time.Now().In(cstSh).Format("2006-01-02") + FileSuffix

	logier, err := rotatelogs.New(
		logFullPath+".%Y%m%d"+FileSuffix,
		rotatelogs.WithLinkName(logFullPath),      // 生成软链，指向最新日志文件
		rotatelogs.WithRotationCount(save),        // 文件最大保存份数
		rotatelogs.WithRotationTime(time.Hour*24), // 日志切割时间间隔
	)

	if err != nil {
		panic(err)
	}
	return logier
}

type MineFormatter struct{}

func (s *MineFormatter) Format(entry *logrus.Entry) ([]byte, error) {

	msg := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Local().Format("2006-01-02 15:04:05"), strings.ToUpper(entry.Level.String()), entry.Message)

	return []byte(msg), nil
}
