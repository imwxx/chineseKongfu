# 1.chineseKongfu

- **What**: Used to configure domain name resolution policy routing, config was suitable for OpenWRT

# 2.How
- **^_^**: This application depends on dnsmasq(with-ipset), ipset, iproute, iptables
## 2.1.config
```
#create config like this
k@k-ThinkPad-P15-Gen-1:~$ /usr/bin/chineseKongfu -c 1 -f /etc/config
{"level":"info","msg":"create /etc/config/chineseKongfu successed","time":"2022-10-25T18:49:43+08:00"}
k@k-ThinkPad-P15-Gen-1:~$ cat /etc/config/chineseKongfu

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
	#获取域名配置，也可以是不加密的配置文件，但是每个域名需要换行
	option url 'https://aaaaa'
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

```

## 2.2.run
```
/usr/bin/chineseKongfu -f /etc/config
```
