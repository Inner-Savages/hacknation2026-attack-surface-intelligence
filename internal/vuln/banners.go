package vuln

import (
	"regexp"
	"strings"
)

// bannerRule parses one banner shape into a product name (resolved through
// the same table as fingerprint detections) and a version.
type bannerRule struct {
	re      *regexp.Regexp
	product string
}

// bannerRules cover the banners a gentle control scan can realistically
// collect: protocols that volunteer a version string on connect or in a
// Server header. Order matters: the first match wins.
var bannerRules = []bannerRule{
	{regexp.MustCompile(`^SSH-[\d.]+-OpenSSH[_-]([\d.]+)`), "OpenSSH"},
	{regexp.MustCompile(`^SSH-[\d.]+-dropbear[_-]?([\d.]+)`), "dropbear"},
	{regexp.MustCompile(`(?i)\bApache/([\d.]+)`), "Apache httpd"},
	{regexp.MustCompile(`(?i)\bnginx/([\d.]+)`), "nginx"},
	{regexp.MustCompile(`(?i)\bopenresty/([\d.]+)`), "OpenResty"},
	{regexp.MustCompile(`(?i)\bMicrosoft-IIS/([\d.]+)`), "Microsoft IIS"},
	{regexp.MustCompile(`(?i)\blighttpd/([\d.]+)`), "lighttpd"},
	{regexp.MustCompile(`(?i)\bProFTPD[ /]([\d.]+)`), "ProFTPD"},
	{regexp.MustCompile(`(?i)\bvsftpd ([\d.]+)`), "vsftpd"},
	{regexp.MustCompile(`(?i)\bExim ([\d.]+)`), "Exim"},
	{regexp.MustCompile(`(?i)\bPostfix(?:/([\d.]+))?`), "Postfix"},
	{regexp.MustCompile(`(?i)\bMySQL (?:Community Server )?(?:\(GPL\) )?([0-9]+\.[0-9]+\.[0-9]+)`), "MySQL"},
	{regexp.MustCompile(`(?i)\bMariaDB[- ]([0-9]+\.[0-9]+\.[0-9]+)`), "MariaDB"},
	{regexp.MustCompile(`(?i)\bredis_version:([0-9]+\.[0-9]+\.[0-9]+)`), "Redis"},
	{regexp.MustCompile(`(?i)"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"`), "Elasticsearch"},
	{regexp.MustCompile(`(?i)\bPostgreSQL ([0-9]+\.[0-9]+)`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)\bOpenVPN ([\d.]+)`), "OpenVPN"},
	{regexp.MustCompile(`(?i)\bTomcat/([\d.]+)`), "Tomcat"},
	{regexp.MustCompile(`(?i)\bWordPress/([\d.]+)`), "WordPress"},
	{regexp.MustCompile(`(?i)\bPHP/([\d.]+)`), "PHP"},
}

// ParseBanner extracts a product name and version from a service banner or
// Server header value. Reports false when nothing recognizable is there.
func ParseBanner(banner string) (product, version string, ok bool) {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "", "", false
	}
	for _, rule := range bannerRules {
		if m := rule.re.FindStringSubmatch(banner); m != nil {
			v := ""
			if len(m) > 1 {
				v = m[1]
			}
			if v == "" {
				continue // a name without a version cannot build a useful CPE
			}
			return rule.product, v, true
		}
	}
	return "", "", false
}

// CPEForBanner combines ParseBanner with CPE construction.
func CPEForBanner(banner string) (string, bool) {
	product, version, ok := ParseBanner(banner)
	if !ok {
		return "", false
	}
	return CPE(ProductFor(product), version), true
}
