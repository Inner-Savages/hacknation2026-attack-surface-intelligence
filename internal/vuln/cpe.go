// Package vuln turns detected technologies (name + version from
// fingerprinting, or a banner grabbed by a control scan) into a ranked list
// of known vulnerabilities: the product maps to a CPE, the CPE is looked up
// in NVD, and every CVE is scored with FIRST's EPSS (exploitation
// probability) and flagged when CISA lists it as Known Exploited. The
// result is a risk ranking instead of a flat list of changes — the
// difference between "something moved" and "this WordPress instance runs
// CVE-XXXX with EPSS 0.87".
//
// All three upstream sources are free, key-optional and cached on disk, so
// repeated scans of the same products cost no quota. Every lookup fails
// soft: without network access the enrichment is simply absent.
package vuln

import (
	"fmt"
	"strings"
)

// Product is the CPE vendor/product pair for one of the technologies our
// signatures recognize.
type Product struct {
	Vendor string
	Name   string
}

// cpeTable maps normalized technology names (lowercase) to their CPE
// vendor/product, following the NVD CPE dictionary.
var cpeTable = map[string]Product{
	"wordpress":                   {"wordpress", "wordpress"},
	"phpmyadmin":                  {"phpmyadmin", "phpmyadmin"},
	"adminer":                     {"adminer", "adminer"},
	"gitea":                       {"gitea", "gitea"},
	"grafana":                     {"grafana", "grafana"},
	"jenkins":                     {"jenkins", "jenkins"},
	"traefik":                     {"traefik", "traefik"},
	"traefik dashboard":           {"traefik", "traefik"},
	"rabbitmq":                    {"pivotal_software", "rabbitmq"},
	"rabbitmq management":         {"pivotal_software", "rabbitmq"},
	"nginx":                       {"nginx", "nginx"},
	"openresty":                   {"openresty", "openresty"},
	"apache httpd":                {"apache", "http_server"},
	"apache":                      {"apache", "http_server"},
	"microsoft iis":               {"microsoft", "internet_information_services"},
	"iis":                         {"microsoft", "internet_information_services"},
	"lighttpd":                    {"lighttpd", "lighttpd"},
	"gunicorn":                    {"gunicorn", "gunicorn"},
	"cowboy":                      {"ninenines", "cowboy"},
	"goahead embedded web server": {"embedthis", "goahead"},
	"openssh":                     {"openbsd", "openssh"},
	"dropbear":                    {"dropbear_ssh_project", "dropbear_ssh"},
	"postgresql":                  {"postgresql", "postgresql"},
	"mysql":                       {"oracle", "mysql"},
	"mariadb":                     {"mariadb", "mariadb"},
	"redis":                       {"redis", "redis"},
	"elasticsearch":               {"elastic", "elasticsearch"},
	"mongodb":                     {"mongodb", "mongodb"},
	"vsftpd":                      {"vsftpd", "vsftpd"},
	"proftpd":                     {"proftpd", "proftpd"},
	"exim":                        {"exim", "exim"},
	"postfix":                     {"postfix", "postfix"},
	"php":                         {"php", "php"},
	"asp.net":                     {"microsoft", "asp.net"},
	"joomla":                      {"joomla", "joomla!"},
	"drupal":                      {"drupal", "drupal"},
	"tomcat":                      {"apache", "tomcat"},
	"mikrotik routeros":           {"mikrotik", "routeros"},
	"routeros":                    {"mikrotik", "routeros"},
	"node.js":                     {"nodejs", "node.js"},
	"express":                     {"expressjs", "express"},
	"django":                      {"djangoproject", "django"},
	"rails":                       {"rubyonrails", "rails"},
	"laravel":                     {"laravel", "laravel"},
	"next.js":                     {"vercel", "next.js"},
	"tomcat manager":              {"apache", "tomcat"},
	"weblogic":                    {"oracle", "weblogic_server"},
	"struts":                      {"apache", "struts"},
	"confluence":                  {"atlassian", "confluence"},
	"atlassian confluence":        {"atlassian", "confluence"},
	"jira":                        {"atlassian", "jira"},
	"gitlab":                      {"gitlab", "gitlab"},
	"minio":                       {"minio", "minio"},
	"kubernetes":                  {"kubernetes", "kubernetes"},
	"docker":                      {"docker", "docker"},
	"prometheus":                  {"prometheus", "prometheus"},
	"vault":                       {"hashicorp", "vault"},
	"consul":                      {"hashicorp", "consul"},
	"roundcube":                   {"roundcube", "webmail"},
	"owncloud":                    {"owncloud", "owncloud"},
	"nextcloud":                   {"nextcloud", "nextcloud"},
}

// ProductFor resolves a detected technology name to its CPE vendor/product.
// Unknown names fall back to a normalized guess (vendor == product): NVD
// returns nothing for a guess that is wrong, which is a safe failure.
func ProductFor(name string) Product {
	key := strings.ToLower(strings.TrimSpace(name))
	if p, ok := cpeTable[key]; ok {
		return p
	}
	norm := strings.NewReplacer(" ", "_", "-", "_").Replace(key)
	return Product{Vendor: norm, Name: norm}
}

// CPE builds a CPE 2.3 formatted string for an application product at an
// exact version. NVD evaluates version ranges in CVE configurations
// against it, so an exact version is what makes the lookup meaningful.
func CPE(p Product, version string) string {
	version = strings.TrimSpace(version)
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", cpeEscape(p.Vendor), cpeEscape(p.Name), cpeEscape(version))
}

// CPEFor combines ProductFor and CPE; reports false when no usable version
// is known (a versionless lookup would return every CVE ever assigned to
// the product — noise, not intelligence).
func CPEFor(name, version string) (string, bool) {
	if strings.TrimSpace(version) == "" {
		return "", false
	}
	return CPE(ProductFor(name), version), true
}

// cpeEscape applies the CPE 2.3 formatted-string quoting for the characters
// common in product names (everything else passes through). Dots stay
// unescaped: NVD registers versions like 2.4.49 verbatim.
func cpeEscape(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	r := strings.NewReplacer(
		" ", "_",
		`!`, `\!`,
		`/`, `\/`,
	)
	return r.Replace(s)
}
