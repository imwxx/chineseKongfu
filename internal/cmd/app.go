package cmd

import (
	"os/exec"
	"sync"
	"time"

	"github.com/imwxx/chineseKongfu/internal/logic"
	"github.com/imwxx/chineseKongfu/internal/model"
	"github.com/sirupsen/logrus"
)

type Run interface {
	Start()
}

type run struct {
	stdOut     *logrus.Logger
	stdErr     *logrus.Logger
	configName string
	configs    string
}

var _ Run = (*run)(nil)

func NewApp(configName, configs string, stdOut, stdErr *logrus.Logger) Run {
	return &run{
		stdOut:     stdOut,
		stdErr:     stdErr,
		configName: configName,
		configs:    configs,
	}
}

func (i *run) DomainsList(config model.KONGFUGROUP, k logic.KongFu) error {
	if config.URL != "" {
		if raw, err := k.GetDomainsList(config.URL, config.DNSMASQD, config.FILENAME, config.DNSSERVER, config.IPSETNAME, config.DECRYPTIONTYPE); err == nil && len(raw) != 0 {
			i.stdOut.Info("get domains successed")
			if err := k.WriteDomainsList(raw, config.FILENAME, config.DNSMASQD, config.DNSSERVER, config.DNSPORT, config.IPSETNAME, config.USEIPSET, config.ADDRESSS); err == nil {
				i.stdOut.Infof(`save %s/%s successed`, config.DNSMASQD, config.FILENAME)
				_, err = exec.Command("sh", "-c", "/etc/init.d/dnsmasq restart").Output()
				if err != nil {
					return err
				} else {
					i.stdOut.Info("dnsmasq reload new config successed")
				}
			} else {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

func (i *run) Start() {
	var n int

	c := logic.NewConfig(i.configName, i.configs)
	configs, err := c.LoadConfig()
	if err != nil {
		i.stdErr.Errorf(`loadconfig %s/%s, error: %s`, i.configs, i.configName, err.Error())
		return
	}

	for _, config := range configs {
		k := logic.NewKongFu(config)

		if err := k.CreateIPsetInRttable(config.IPSETNAME, config.RTTABLES, config.LOOKUP); err == nil {
			i.stdOut.Infof(`step 1: add ipset config "%d %s" into %s successed`, config.LOOKUP, config.IPSETNAME, config.RTTABLES)
		} else {
			i.stdOut.Errorf(`step 1: add ipset config "%d %s" into %s error: %s`, config.LOOKUP, config.IPSETNAME, config.RTTABLES, err.Error())
		}

		if err := k.CreateIpset(config.IPSETNAME, config.IPSETTYPE); err == nil {
			i.stdOut.Infof(`step 2: create ipset SETNAME: %s, successed`, config.IPSETNAME)
		} else {
			i.stdErr.Errorf(`step 2: create ipset SETNAME: %s, error: %s`, config.IPSETNAME, err.Error())
		}

		if err := k.CreateRoute(config.LOOKUP, config.INTERFACE); err == nil {
			i.stdOut.Infof(`step 3: create route successed: target: 0.0.0.0/0, table: %d, interface: %s`, config.LOOKUP, config.INTERFACE)
			if err := k.CreateRule(config.LOOKUP, config.MARK); err == nil {
				i.stdOut.Infof(`step 4: create rule: mark: %d, lookup: %d, successed`, config.MARK, config.LOOKUP)
			} else {
				i.stdOut.Errorf(`step 4: create rule: mark: %d, lookup: %d, error: %s`, config.MARK, config.LOOKUP, err.Error())
			}
		} else {
			i.stdOut.Errorf(`step 3: create route: target: 0.0.0.0/0, table: %d, interface: %s, error: %s`, config.LOOKUP, config.INTERFACE, err.Error())
		}

		if len(config.HOSTS) != 0 {
			if err := k.AddHostToIpset(config.IPSETNAME, config.IPSETTYPE, config.HOSTS); err == nil {
				i.stdOut.Infof(`step 5: add %d hosts into ipset: %s successed`, len(config.HOSTS), config.IPSETNAME)
			} else {
				i.stdOut.Errorf(`step 5: add %d hosts into ipset: %s, error: %s`, len(config.HOSTS), config.IPSETNAME, err.Error())
			}
		}

		if err := i.DomainsList(config, k); err != nil {
			i.stdErr.Errorf(`step 6: domains file saved failed, error: %s`, err.Error())
		} else {
			i.stdOut.Info("step 6: domains file saved successed")
		}

		if err := k.CreateIptables(config.IPSETNAME, config.MARK); err != nil {
			i.stdErr.Errorf(`step 7: create iptables error: %s`, err.Error())
		} else {
			i.stdOut.Info("step 7: create iptables successed")
		}

		if config.UPDATE {
			n += 1
		}
	}

	var wg sync.WaitGroup
	wg.Add(n)
	ch := make(chan error, n)

	for _, config := range configs {
		k := logic.NewKongFu(config)
		go func(config model.KONGFUGROUP, k logic.KongFu) {
			if config.UPDATE {
				for {
					time.Sleep(time.Hour * time.Duration(config.TTL))
					if err := i.DomainsList(config, k); err != nil {
						defer wg.Done()
						ch <- err
					}
				}
			}
		}(config, k)
	}

	for m := range ch {
		n -= 1
		if m != nil {
			i.stdErr.Error(m.Error())
		}
		if n == 0 {
			close(ch)
		}
	}

}
