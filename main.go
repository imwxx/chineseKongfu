package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/imwxx/chineseKongfu/internal/cmd"
	"github.com/sirupsen/logrus"
)

type Flags struct {
	file string
	show string
}

var file = "/etc/config"

var show = `
config kongfu
	#是否启用ipset，若启用 ipsetname, ipsettype, rttables字段为必须字段
	option useipset '1'
	#创建ipset配置名称
	option ipsetname 'workspace'
	#创建ipset配置类型，建议优先用hash:ip,net 或 hash:ip
	option ipsettype 'hash:ip,net'
	#iproute配置路径
	option rttables '/etc/iproute2/rt_tables'
	#策略路由优先级
	option lookup '99'
	#策略路由标识
	option mark '2'
	#网络接口
	option interface 'ocvpn'
	#获取域名列表配置，也可以是不加密的配置文件，但是每个域名需要换行
	option url 'https://raw.githubusercontent.com/workspace/workspace/master/workspace.txt'
	#workspace配置加密类似，也可以不加密,不加密的话decryptiontype配置值为normal
	option decryptiontype 'base64'
	#dnsmasq配置目录
	option dnsmasqd '/etc/dnsmasq.d'
	#url下载的文件保持名称
	option filename 'workspace'
	#url对应的内容是否自动更新, 1自动更新，0不自动更新
	option update '1'
	#更新的周期，单位为小时
	option ttl '720'
	#gfw配置对应用于解析的DNS地址
	option dnsserver '8.8.8.8'
	#DNS端口
	option dnsport '53'
	#其他特殊配置，没在workspace中体现的
	list address '/cf.wxx.com/192.168.40.56#53'
	list address '/jira.wxx.com/192.168.40.56#53'
	#其他需要走策略路由的IP或者IP段
	list hosts '192.168.2.0/24'
	list hosts '192.168.3.10'
`

func parseFlags() *Flags {
	argsflag := new(Flags)
	flag.StringVar(&argsflag.file, "f", file, "config dir, default /etc/config")
	flag.StringVar(&argsflag.show, "c", "0", "create sample config demo to /etc/config/chineseKongfu, use value 1")
	flag.Parse()
	return argsflag
}

func main() {
	stdErr := logrus.New()
	stdErr.Formatter = &logrus.JSONFormatter{}
	stdErr.Level = logrus.InfoLevel
	stdErr.Out = os.Stderr

	stdOut := logrus.New()
	stdOut.Formatter = &logrus.JSONFormatter{}
	stdOut.Level = logrus.InfoLevel
	stdOut.Out = os.Stdout

	argsflag := parseFlags()
	file := argsflag.file
	fileName := "chineseKongfu"
	configFile := fmt.Sprintf(`%s/%s`, file, fileName)

	if argsflag.show == "1" {
		if _, err := os.Stat(file); err != nil {
			if err := os.Mkdir(file, os.ModePerm); err != nil {
				stdErr.Error(err)
				os.Exit(1)
			}
		}
		if _, err := os.Stat(configFile); err != nil {
			f, err := os.Create(configFile)
			if err != nil {
				stdErr.Error(err)
				os.Exit(1)
			}
			defer f.Close()
			if _, err := f.WriteString(show); err != nil {
				stdErr.Error(err)
				os.Exit(1)
			} else {
				stdOut.Infof(`create %s successed`, configFile)
			}
		}
		os.Exit(0)
	}

	app := cmd.NewApp(fileName, file, stdOut, stdErr)
	app.Start()
}
