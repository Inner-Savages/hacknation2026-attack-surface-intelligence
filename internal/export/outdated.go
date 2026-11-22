package export

import (
	"regexp"
	"strconv"
	"strings"
)

// minSupported lists, per technology, a release line everything older than
// which is certainly out of upstream support (as of November 2026). It is
// deliberately short and conservative: a version below it is worth a look,
// not proof of a vulnerability (distributions backport fixes). Proper CVE
// matching is a separate concern.
var minSupported = map[string]string{
	"Apache httpd": "2.4",
	"Drupal":       "10",
	"gunicorn":     "20",
	"MariaDB":      "10.6",
	"MySQL":        "8.0",
	"nginx":        "1.26",
	"OpenSSH":      "8.0",
	"PHP":          "8.2",
	"PostgreSQL":   "14",
	"Redis":        "6.2",
	"WordPress":    "6.0",
}

// exactVersion matches a concrete version ("1.18.0", "9.6p1 Ubuntu 3").
// nmap also reports guesses such as "9.6.0 or later" or "12.3 - 13.1",
// which say nothing about the real version.
var (
	exactVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)
	vagueVersion = regexp.MustCompile(`(?i)\bor (later|earlier|newer|older)\b|\d\s+-\s+v?\d|\bx\b|[*<>]`)
)

// outdated reports whether version is older than what is still supported.
// number is the plain dotted version and oldest the first release line that
// is not outdated.
func outdated(tech, version string) (number, oldest string, ok bool) {
	oldest, known := minSupported[tech]
	m := exactVersion.FindStringSubmatch(version)
	if !known || m == nil || vagueVersion.MatchString(version) {
		return "", "", false
	}
	return m[1], oldest, versionLess(m[1], oldest)
}

// versionLess compares dotted versions over the components both have: "8"
// is not older than "8.0", because the minor version is simply not known.
func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, errX := strconv.Atoi(as[i])
		y, errY := strconv.Atoi(bs[i])
		if errX != nil || errY != nil {
			return false
		}
		if x != y {
			return x < y
		}
	}
	return false
}
