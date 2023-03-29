package logic

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/imwxx/chineseKongfu/internal/model"
)

type KongFu interface {
	AddHostToIpset(ipsetname string, ipsettype string, hosts []string) error
	CheckIPsetInRttable(ipsetname string, rttables string, lookup int64) error
	CheckIptables(ipsetname string) error
	ChectIpset(ipsetname string) error
	CreateIPsetInRttable(ipsetname string, rttables string, lookup int64) error
	CreateIpset(ipsetname string, ipsettype string) error
	CreateIptables(ipsetname string, mark int64) error
	CreateRoute(lookup int64, wan string) error
	CreateRule(lookup int64, mark int64) error
	Exists(path string) bool
	GetDomainsList(url string, dnsmasqd string, filename string, dnsserver string, ipsetname string, decryptiontype string) ([]string, error)
	WriteDomainsList(raw []string, fileName string, dnsmasqd string, dnsserver string, dnsPort int, ipsetName string, useIpset bool, address []string) error
}

type kongfu struct {
	configs model.KONGFUGROUP
	sync.Mutex
}

var _ KongFu = (*kongfu)(nil)

func NewKongFu(configs model.KONGFUGROUP) KongFu {
	return &kongfu{
		configs: configs,
	}
}

func (i *kongfu) CheckIPsetInRttable(ipsetname, rttables string, lookup int64) error {
	var err error
	str := fmt.Sprintf(`%d %s`, lookup, ipsetname)

	_, err = exec.Command("grep", "-w", str, rttables).Output()
	if err != nil {
		return err
	}

	return err
}

func (i *kongfu) CreateIPsetInRttable(ipsetname, rttables string, lookup int64) error {
	i.Lock()
	defer i.Unlock()

	if _, err := os.Stat(rttables); os.IsNotExist(err) {
		return err
	}

	if err := i.CheckIPsetInRttable(ipsetname, rttables, lookup); err != nil {
		str := fmt.Sprintf(`%d %s`, lookup, ipsetname)
		f, ferr := os.OpenFile(rttables, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if ferr != nil {
			return ferr
		}
		_, err := io.WriteString(f, str+"\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *kongfu) ChectIpset(ipsetname string) error {
	out, err := exec.Command("ipset", "list", ipsetname).Output()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

func (i *kongfu) CreateIpset(ipsetname, ipsettype string) error {
	if err := i.ChectIpset(ipsetname); err != nil {
		out, err := exec.Command("ipset", "create", ipsetname, ipsettype).Output()
		if err != nil {
			return errors.New(string(out))
		}
	}
	return nil
}

func (i *kongfu) AddHostToIpset(ipsetname, ipsettype string, hosts []string) error {
	if err := i.CreateIpset(ipsetname, ipsettype); err != nil {
		return err
	}

	for _, host := range hosts {
		out, err := exec.Command("ipset", "add", ipsetname, host).Output()
		if err != nil {
			return errors.New(string(out))
		}
	}
	return nil
}

func (i *kongfu) CheckRoute(lookup int64) error {
	c := fmt.Sprintf(`grep "option table '%d'" /etc/config/network`, lookup)
	_, err := exec.Command("sh", "-c", c).Output()
	if err != nil {
		return err
	}
	return nil
}

func (i *kongfu) CheckRule(lookup int64) error {
	c := fmt.Sprintf(`grep "option lookup '%d'" /etc/config/network`, lookup)
	_, err := exec.Command("sh", "-c", c).Output()
	if err != nil {
		return err
	}
	return nil
}

func (i *kongfu) CreateRoute(lookup int64, wan string) error {
	var commands [][]string

	commandsStr := []string{
		"add network route",
		fmt.Sprintf(`set network.@route[-1].target=%s`, "0.0.0.0/0"),
		fmt.Sprintf(`set network.@route[-1].table=%d`, lookup),
		fmt.Sprintf(`set network.@route[-1].interface=%s`, wan),
		"commit network",
	}
	for _, cstr := range commandsStr {
		args := strings.Split(cstr, " ")
		commands = append(commands, args)
	}
	if err := i.CheckRoute(lookup); err != nil {
		for _, command := range commands {
			if _, err := exec.Command("uci", command...).Output(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (i *kongfu) CreateRule(lookup, mark int64) error {
	var commands [][]string
	commandsStr := []string{
		"add network rule",
		fmt.Sprintf(`set network.@rule[-1].mark=%#x`, mark),
		fmt.Sprintf(`set network.@rule[-1].lookup=%d`, lookup),
		"commit network",
	}
	for _, cstr := range commandsStr {
		args := strings.Split(cstr, " ")
		commands = append(commands, args)
	}
	if err := i.CheckRule(lookup); err != nil {
		for _, command := range commands {
			if _, err := exec.Command("uci", command...).Output(); err != nil {
				return err
			}
		}
		if _, err := exec.Command("sh", "-c", "/etc/init.d/network restart").Output(); err != nil {
			return errors.New("/etc/init.d/network restart error")
		}

	}
	return nil
}

func (i *kongfu) GetDomainsList(url, dnsmasqd, filename, dnsserver, ipsetname, decryptiontype string) ([]string, error) {
	domainsMap := make(map[string]string)
	domains := []string{}
	domainsExt := []string{
		"google.com",
		"google.com.hk",
		"google.com.tw",
		"google.com.sg",
		"google.co.jp",
		"google.co.kr",
		"blogspot.com",
		"blogspot.sg",
		"blogspot.hk",
		"blogspot.jp",
		"blogspot.kr",
		"gvt1.com",
		"gvt2.com",
		"gvt3.com",
		"1e100.net",
		"blogspot.tw",
	}

	commentPatternReg := regexp.MustCompile(`^\!|\[|^@@|^\d+\.\d+\.\d+\.\d+`)
	domainPatternReg := regexp.MustCompile(`(?:[\w\-]*\*[\w\-]*\.)?([\w\-]+\.[\w\.\-]+)[\/\*]*`)
	reg := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return domains, err
	}
	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return domains, err
	}

	switch decryptiontype {
	case "base64":
		decRaw, err := base64.StdEncoding.DecodeString(string(rawBody))
		if err != nil {
			return domains, err
		}
		rawList := strings.Split(string(decRaw), "\n")
		for _, raw := range rawList {
			words := commentPatternReg.FindAllStringSubmatch(raw, -1)
			if len(words) == 0 {
				domains := domainPatternReg.FindAllStringSubmatch(raw, 1)
				if len(domains) != 0 {
					domain := domains[0][1]
					if !reg.MatchString(domain) {
						domainsMap[domain] = domain
					}
				}

			}
		}

	case "normal":
		rawList := strings.Split(string(rawBody), "\n")
		for _, raw := range rawList {
			domains := domainPatternReg.FindAllStringSubmatch(raw, 1)
			if len(domains) != 0 {
				domain := domains[0][1]
				if !reg.MatchString(domain) {
					domainsMap[domain] = domain
				}
			}
		}
	}

	if len(domainsMap) != 0 {
		for _, domain := range domainsMap {
			domains = append(domains, domain)
		}
		domains = append(domains, domainsExt...)
	}
	return domains, nil
}

func (i *kongfu) Exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func (i *kongfu) WriteDomainsList(raw []string, fileName, dnsmasqd, dnsserver string, dnsPort int, ipsetName string, useIpset bool, address []string) error {
	i.Lock()
	defer i.Unlock()

	var err error
	var f *os.File
	file := fmt.Sprintf(`%s/%s.conf`, dnsmasqd, fileName)

	if !i.Exists(dnsmasqd) {
		if err := os.Mkdir(dnsmasqd, 0755); err != nil {
			return err
		}
		if f, err := os.OpenFile("/etc/dnsmasq.conf", os.O_APPEND|os.O_WRONLY, os.ModeAppend); err != nil {
			return err
		} else {
			if _, err = io.WriteString(f, "conf-dir = /etc/dnsmasq.d"+"\n"); err != nil {
				return err
			}
		}

	}
	if i.Exists(file) {
		f, err = os.OpenFile(file, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0666)
		if err != nil {
			return err
		}
	} else {
		f, err = os.Create(file)
		if err != nil {
			return err
		}
	}
	defer f.Close()

	for _, domain := range raw {
		server := fmt.Sprintf(`server=/%s/%s#%d`, domain, dnsserver, dnsPort)
		_, err = io.WriteString(f, server)
		if err != nil {
			return err
		}
		f.WriteString("\n")

		if useIpset {
			ipset := fmt.Sprintf(`ipset=/%s/%s`, domain, ipsetName)
			_, err = io.WriteString(f, ipset)
			if err != nil {
				return err
			}
			f.WriteString("\n")
		}
	}

	for _, add := range address {
		server := fmt.Sprintf(`server=%s`, add)
		_, err = io.WriteString(f, server)
		if err != nil {
			return err
		}
		f.WriteString("\n")
	}

	return nil
}

func (i *kongfu) CheckIptables(ipsetname string) error {
	_, err := exec.Command("/usr/sbin/iptables", "-t", "mangle", "-nvL", ipsetname).Output()
	if err != nil {
		return err
	}
	return nil
}

func (i *kongfu) CreateIptables(ipsetname string, mark int64) error {
	if err := i.CheckIptables(ipsetname); err != nil {
		f, err := os.OpenFile("/etc/firewall.user", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if err != nil {
			return err
		}
		defer f.Close()

		iptables := []string{
			fmt.Sprintf(`iptables -t mangle -N %s`, ipsetname),
			fmt.Sprintf(`iptables -t mangle -I PREROUTING -m set --match-set %s dst -j MARK --set-mark %d`, ipsetname, mark),
			fmt.Sprintf(`iptables -t mangle -A OUTPUT -j %s`, ipsetname),
			fmt.Sprintf(`iptables -t mangle -A %s -m set --match-set %s dst -j MARK --set-mark %d`, ipsetname, ipsetname, mark),
			fmt.Sprintf(`iptables -t nat -A POSTROUTING -m mark --mark %#x -j MASQUERADE`, mark),
		}

		for _, table := range iptables {
			_, err = io.WriteString(f, table)
			if err != nil {
				return err
			}
			f.WriteString("\n")
		}
		f.WriteString("\n")

		_, err = exec.Command("sh", "-c", "/etc/init.d/firewall restart").Output()
		if err != nil {
			return errors.New(fmt.Sprintf(`step 8: firewall restart failed: %s`, err.Error()))
		}
	}
	return nil
}
