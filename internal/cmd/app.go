package cmd

import (
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
		i.stdErr.Error(err.Error())
		return
	}

	for _, config := range configs {
		k := logic.NewKongFu(config)
		if config.USEIPSET {
			if err := k.CreateIPsetInRttable(config.IPSETNAME, config.RTTABLES, config.LOOKUP); err == nil {
				i.stdOut.Infof(`add ipset config "%d %s" into %s successed`, config.LOOKUP, config.IPSETNAME, config.RTTABLES)
			} else {
				i.stdErr.Error(err.Error())
			}
			if err := k.CreateIpset(config.IPSETNAME, config.IPSETTYPE); err == nil {
				i.stdOut.Infof(`ipset create %s %s, successed`, config.IPSETNAME, config.RTTABLES)
			} else {
				i.stdErr.Error(err.Error())
			}

			if err := k.CreateRoute(config.LOOKUP, config.INTERFACE); err == nil {
				i.stdOut.Infof(`create route successed: target: 0.0.0.0/0, table: %d, interface: %s`, config.LOOKUP, config.INTERFACE)
				if err := k.CreateRule(config.LOOKUP, config.MARK); err == nil {

				} else {
					i.stdErr.Error(err.Error())
				}
			} else {
				i.stdErr.Error(err.Error())
			}
			if len(config.HOSTS) != 0 {
				if err := k.AddHostToIpset(config.IPSETNAME, config.IPSETTYPE, config.HOSTS); err == nil {
					i.stdOut.Infof(`add %d hosts into ipset: %s successed`, config.IPSETNAME, len(config.HOSTS))
				} else {
					i.stdErr.Error(err.Error())
				}
			}
		}

		if err := k.CreateIptables(config.IPSETNAME, config.MARK); err != nil {
			i.stdErr.Error(err.Error())
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
					if err := i.DomainsList(config, k); err != nil {
						defer wg.Done()
						ch <- err
					}
					time.Sleep(time.Hour * time.Duration(config.TTL))
				}
			} else {
				if err := i.DomainsList(config, k); err != nil {
					i.stdErr.Error(err.Error())
				} else {
					i.stdOut.Info("domains file saved successed")
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
