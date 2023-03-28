package model

type KONGFUGROUP struct {
	USEIPSET      bool
	IPSETNAME     string
	IPSETTYPE     string
	RTTABLES       string
	LOOKUP        int64
	MARK          int64
	INTERFACE     string
	URL           string
	DECRYPTIONTYPE string
	DNSMASQD      string
	FILENAME      string
	UPDATE        bool
	TTL           int64
	DNSSERVER     string
	DNSPORT       int
	ADDRESSS      []string
	HOSTS         []string
}
