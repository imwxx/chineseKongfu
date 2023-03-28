package logic

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/digineo/go-uci"
	"github.com/imwxx/chineseKongfu/internal/model"
)

type Config interface {
	LoadConfig() ([]model.KONGFUGROUP, error)
}

type config struct {
	configName string
	uci        uci.Tree
	sync.Mutex
}

var _ Config = (*config)(nil)

func NewConfig(configName, configs string) Config {
	return &config{
		configName: configName,
		uci:        uci.NewTree(configs),
	}
}

func (i *config) LoadConfig() ([]model.KONGFUGROUP, error) {
	data := []model.KONGFUGROUP{}
	fields := []string{}
	sections, ok := i.uci.GetSections(i.configName, "kongfu")
	if !ok {
		return data, errors.New("get sections: kongfu, error")
	}

	s := model.KONGFUGROUP{}
	sType := reflect.TypeOf(s)

	for i := 0; i < sType.NumField(); i++ {
		fieldType := sType.Field(i)
		fields = append(fields, fieldType.Name)
	}

	for _, section := range sections {
		var config model.KONGFUGROUP
		for _, name := range fields {
			if val, ok := i.uci.Get(i.configName, section, strings.ToLower(name)); ok {
				switch name {
				case "USEIPSET":
					use, _ := strconv.Atoi(val[0])
					b := false
					if use == 1 {
						b = true
					}
					config.USEIPSET = b
				case "IPSETNAME":
					config.IPSETNAME = val[0]
				case "IPSETTYPE":
					config.IPSETTYPE = val[0]
				case "RTTABLES":
					config.RTTABLES = val[0]
				case "LOOKUP":
					lookup, err := strconv.Atoi(val[0])
					if err == nil {
						config.LOOKUP = int64(lookup)
					}
				case "MARK":
					mark, err := strconv.Atoi(val[0])
					if err != nil {
						config.MARK = int64(mark)
					}
				case "INTERFACE":
					config.INTERFACE = val[0]
				case "URL":
					config.URL = val[0]
				case "DECRYPTIONTYPE":
					if len(val) == 0 {
						config.DECRYPTIONTYPE = "normal"
					} else {
						config.DECRYPTIONTYPE = val[0]
					}
				case "DNSMASQD":
					config.DNSMASQD = val[0]
				case "FILENAME":
					config.FILENAME = val[0]
				case "UPDATE":
					update, _ := strconv.Atoi(val[0])
					if update == 1 {
						config.UPDATE = true
					} else {
						config.UPDATE = false
					}
				case "TTL":
					ttl, _ := strconv.Atoi(val[0])
					config.TTL = int64(ttl)
				case "DNSSERVER":
					config.DNSSERVER = val[0]
				case "DNSPORT":
					config.DNSPORT, _ = strconv.Atoi(val[0])
				case "ADDRESSS":
					config.ADDRESSS = val
				case "HOSTS":
					config.HOSTS = val
				}
			}
		}
		data = append(data, config)
	}
	return data, nil
}
