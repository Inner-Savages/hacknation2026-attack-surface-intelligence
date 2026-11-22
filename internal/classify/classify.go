// Package classify turns the signals a passive sensor already sees — the
// OUI half of a MAC address, observed open ports, banners and TLS
// certificate subjects — into a device-class label: printer, camera, IoT
// gadget, server, workstation, network gear, phone. It is the classifier
// behind the console's CMDB-from-traffic inventory: no probing, no extra
// traffic, only conclusions from evidence that was on the wire anyway.
//
// The OUI table is deliberately a curated subset of the IEEE registry —
// vendors common in office and server-room networks, each with a class
// hint. Swapping it for the full IEEE list (or a generated table) changes
// coverage, not the API.
package classify

import (
	"sort"
	"strings"
)

// Device classes. The values are Polish because they are displayed verbatim
// in the operator console and persisted in the host registry.
const (
	Unknown     = "nieznane"
	Printer     = "drukarka"
	Camera      = "kamera"
	IoT         = "iot"
	Server      = "serwer"
	Workstation = "stacja"
	Network     = "sieciowe" // router, switch, access point
	Phone       = "telefon"
	Container   = "kontener" // Docker/OCI container (locally administered MAC 02:42:…)
	Gateway     = "brama"    // container-bridge gateway / host running the containers
	Database    = "baza"     // PostgreSQL, MySQL, MSSQL, MongoDB, Elasticsearch
	Broker      = "broker"   // RabbitMQ/AMQP, Kafka, ActiveMQ
	Git         = "git"      // Gitea, GitLab, Gogs
	Web         = "web"      // web application / HTTP server
	Cache       = "cache"    // Redis, Memcached
	FileServer  = "pliki"    // FTP, SFTP file transfer
)

// Evidence is one reason the classifier believed what it believed — kept so
// the operator can audit every label.
type Evidence struct {
	Source string // "OUI", "port", "banner", "TLS"
	Detail string // human-readable, e.g. "Hikvision (44:19:b6)" or "554 (RTSP)"
}

// Input is everything known about one host from passive observation.
type Input struct {
	MAC         string   // source MAC as seen on the wire, e.g. "44:19:b6:00:11:22"
	Ports       []int    // open TCP ports the sensor reported
	Banners     []string // service banners (from control scans)
	TLSSubjects []string // certificate subjects (from TLS probes)
	IP          string   // host address; used to spot the bridge gateway (.1)
	Products    []string // "product version" strings from an imported/scanned result
	Titles      []string // HTTP page titles from an imported/scanned result
}

// Output is the verdict: the winning class, how much evidence backs it and
// why. Vendor is the OUI match, empty when the MAC is unknown or locally
// administered.
type Output struct {
	Class      string
	Confidence float64
	Vendor     string
	Reasons    []Evidence
}

// vote accumulates evidence weight per candidate class.
type vote struct {
	weight float64
	proofs []Evidence
}

// Classify folds all input signals into one label. Each signal votes with a
// weight; the strongest total wins, ties break towards the class with more
// independent sources. Confidence is the winner's total capped at 0.98.
func Classify(in Input) Output {
	votes := map[string]*vote{}
	add := func(class string, w float64, ev Evidence) {
		v := votes[class]
		if v == nil {
			v = &vote{}
			votes[class] = v
		}
		v.weight += w
		v.proofs = append(v.proofs, ev)
	}

	out := Output{Class: Unknown}
	docker := isDockerMAC(in.MAC)
	var platform *Evidence
	if vendor, class, ok := lookupOUI(in.MAC); ok {
		out.Vendor = vendor
		add(class, 0.8, Evidence{Source: "OUI", Detail: vendor + " (" + ouiPrefix(in.MAC) + ")"})
	} else if docker {
		out.Vendor = "Docker"
		ev := Evidence{Source: "MAC", Detail: "02:42 — kontener Docker (adres lokalny)"}
		platform = &ev
		add(Container, 0.45, ev)
	}
	// A port reported by both the sensor and a scan counts once.
	seenPort := map[int]bool{}
	var ports []int
	for _, p := range in.Ports {
		if !seenPort[p] {
			seenPort[p] = true
			ports = append(ports, p)
		}
	}
	for _, p := range ports {
		if rule, ok := portRules[p]; ok {
			add(rule.class, rule.weight, Evidence{Source: "port", Detail: itoa(p) + " (" + rule.name + ")"})
		}
	}
	type text struct{ s, src string }
	var texts []text
	for _, b := range in.Banners {
		texts = append(texts, text{b, "banner"})
	}
	for _, b := range in.Products {
		texts = append(texts, text{b, "produkt"})
	}
	for _, b := range in.Titles {
		texts = append(texts, text{b, "tytuł HTTP"})
	}
	for _, b := range in.TLSSubjects {
		texts = append(texts, text{b, "TLS"})
	}
	for _, t := range texts {
		low := strings.ToLower(t.s)
		if low == "" {
			continue
		}
		for _, kw := range bannerRules {
			if strings.Contains(low, kw.substr) {
				add(kw.class, kw.weight, Evidence{Source: t.src, Detail: quote(t.s) + " → " + kw.substr})
			}
		}
	}
	// Bridge gateway: x.x.x.1 whose only visible service is SSH (the VM host
	// reaching the container network), or nothing at all, on a Docker MAC.
	if gw := gatewayEvidence(in, ports, docker); gw != nil {
		add(Gateway, 0.9, *gw)
	}

	var best string
	var bv *vote
	// Deterministic order so equal scores always resolve the same way.
	classes := make([]string, 0, len(votes))
	for c := range votes {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		v := votes[c]
		if bv == nil || v.weight > bv.weight || (v.weight == bv.weight && len(v.proofs) > len(bv.proofs)) {
			best, bv = c, v
		}
	}
	if bv == nil {
		return out
	}
	out.Class = best
	out.Reasons = bv.proofs
	// The platform fact (Docker container) is context for every role label.
	if platform != nil && best != Container {
		out.Reasons = append(append([]Evidence{}, bv.proofs...), *platform)
	}
	out.Confidence = bv.weight
	if out.Confidence > 0.98 {
		out.Confidence = 0.98
	}
	return out
}

// isDockerMAC reports whether the MAC is a Docker-assigned address
// (02:42:…, locally administered).
func isDockerMAC(mac string) bool {
	return strings.HasPrefix(stripMAC(mac), "0242")
}

// gatewayEvidence recognises the Docker bridge gateway: the .1 address of a
// container subnet, answering at most on SSH.
func gatewayEvidence(in Input, ports []int, docker bool) *Evidence {
	if !strings.HasSuffix(in.IP, ".1") || strings.Count(in.IP, ".") != 3 {
		return nil
	}
	for _, p := range ports {
		if p != 22 {
			return nil
		}
	}
	if !docker && in.MAC != "" {
		return nil
	}
	d := in.IP + " — adres .1 podsieci"
	if len(ports) == 1 {
		d += ", tylko port 22"
	} else {
		d += ", brak otwartych usług"
	}
	if docker {
		d += ", MAC Docker 02:42"
	}
	return &Evidence{Source: "topologia", Detail: d}
}

// ouiPrefix normalises a MAC to its 6-hex-digit OUI prefix ("44:19:b6").
func ouiPrefix(mac string) string {
	hex := stripMAC(mac)
	if len(hex) < 6 {
		return ""
	}
	return hex[0:2] + ":" + hex[2:4] + ":" + hex[4:6]
}

func stripMAC(mac string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(mac) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lookupOUI matches the first three bytes of a MAC against the vendor
// table. Locally administered addresses (the U/L bit set, e.g. Docker's
// 02:42:…) carry no vendor information and never match.
func lookupOUI(mac string) (vendor, class string, ok bool) {
	hex := stripMAC(mac)
	if len(hex) < 6 {
		return "", "", false
	}
	entry, found := ouiTable[hex[:6]]
	if !found {
		return "", "", false
	}
	return entry.vendor, entry.class, true
}

type ouiEntry struct {
	vendor string
	class  string
}

// ouiTable maps a 6-hex-digit OUI prefix to a vendor and its most likely
// device class. Curated for office/server-room fleets; extend freely — a
// match votes 0.8, so OUI is the single strongest signal.
var ouiTable = map[string]ouiEntry{
	// IP cameras
	"4419b6": {"Hikvision", Camera}, "c056e3": {"Hikvision", Camera}, "1868cb": {"Hikvision", Camera},
	"688f2e": {"Hikvision", Camera}, "3ce38b": {"Dahua", Camera}, "9002a9": {"Dahua", Camera},
	"246c84": {"Dahua", Camera}, "e0508b": {"Dahua", Camera}, "00408c": {"Axis Communications", Camera},
	"accc8e": {"Axis Communications", Camera},
	// Printers
	"00110a": {"Hewlett-Packard", Printer}, "3c4a92": {"Hewlett-Packard", Printer}, "b499ba": {"Hewlett-Packard", Printer},
	"000085": {"Canon", Printer}, "f48139": {"Canon", Printer}, "000048": {"Seiko Epson", Printer},
	"001ba9": {"Brother", Printer}, "008077": {"Brother", Printer}, "0000aa": {"Xerox", Printer},
	"000074": {"Ricoh", Printer}, "002000": {"Lexmark", Printer},
	// IoT / smart home
	"246f28": {"Espressif (ESP32)", IoT}, "30aea4": {"Espressif (ESP8266/ESP32)", IoT},
	"84f3eb": {"Espressif (ESP32)", IoT}, "b8e62d": {"Espressif", IoT}, "508a06": {"Tuya Smart", IoT},
	"b827eb": {"Raspberry Pi", IoT}, "dca632": {"Raspberry Pi", IoT}, "e45f01": {"Raspberry Pi", IoT},
	"000e58": {"Sonos", IoT}, "5caafd": {"Sonos", IoT}, "949f3e": {"Sonos", IoT},
	"74c246": {"Amazon (Echo/Ring)", IoT}, "f4f5d8": {"Google (Nest/Chromecast)", IoT},
	"546009": {"Google (Nest/Chromecast)", IoT}, "001788": {"Philips Hue (Signify)", IoT},
	"ecb5fa": {"Philips Hue (Signify)", IoT}, "640980": {"Xiaomi", IoT}, "f0b429": {"Xiaomi", IoT},
	// Network gear
	"245a4c": {"Ubiquiti", Network}, "7483c2": {"Ubiquiti", Network}, "788a20": {"Ubiquiti", Network},
	"e063da": {"Ubiquiti", Network}, "50c7bf": {"TP-Link", Network}, "f4f26d": {"TP-Link", Network},
	"a42bb0": {"TP-Link", Network}, "c025e9": {"TP-Link", Network}, "4c5e0c": {"MikroTik", Network},
	"6c3b6b": {"MikroTik", Network}, "b869f4": {"MikroTik", Network}, "d401c3": {"MikroTik", Network},
	"204e7f": {"Netgear", Network}, "841b5e": {"Netgear", Network}, "a06391": {"Netgear", Network},
	"000ff7": {"Cisco", Network}, "001aa1": {"Cisco", Network},
	// Workstations / endpoints
	"3c22fb": {"Apple", Workstation}, "a483e7": {"Apple", Workstation}, "f01898": {"Apple", Workstation},
	"8c8590": {"Apple", Workstation}, "3cf011": {"Intel (karta sieciowa)", Workstation},
	"b083fe": {"Dell", Workstation}, "f8bc12": {"Dell", Workstation}, "d4ae52": {"Dell", Workstation},
	"28d244": {"Lenovo", Workstation}, "6c0b84": {"Lenovo", Workstation}, "68f728": {"Lenovo", Workstation},
	// Servers / virtualisation
	"000c29": {"VMware", Server}, "005056": {"VMware", Server}, "000569": {"VMware", Server},
	"002590": {"Supermicro", Server}, "0cc47a": {"Supermicro", Server},
	// VoIP phones
	"000b82": {"Grandstream", Phone}, "c074ad": {"Grandstream", Phone},
	"805ec0": {"Yealink", Phone}, "001565": {"Yealink", Phone},
}

type portRule struct {
	class  string
	weight float64
	name   string
}

// portRules vote from the service set alone: a port nobody else would open
// is a mid-strength signal (firewalls and forwarded ports keep it below
// OUI). Generic ports (SSH, HTTP) vote weakly: they only decide a class when
// nothing more specific is present, and a Docker MAC alone keeps "kontener".
var portRules = map[int]portRule{
	9100:  {Printer, 0.65, "JetDirect/raw printing"},
	515:   {Printer, 0.6, "LPD"},
	631:   {Printer, 0.6, "IPP"},
	554:   {Camera, 0.7, "RTSP"},
	8554:  {Camera, 0.6, "RTSP (alt)"},
	1883:  {IoT, 0.6, "MQTT"},
	8883:  {IoT, 0.55, "MQTT/TLS"},
	5683:  {IoT, 0.55, "CoAP"},
	3306:  {Database, 0.65, "MySQL"},
	5432:  {Database, 0.65, "PostgreSQL"},
	1433:  {Database, 0.6, "MSSQL"},
	27017: {Database, 0.6, "MongoDB"},
	9200:  {Database, 0.6, "Elasticsearch"},
	6379:  {Cache, 0.6, "Redis"},
	11211: {Cache, 0.55, "Memcached"},
	5672:  {Broker, 0.65, "AMQP/RabbitMQ"},
	15672: {Broker, 0.6, "RabbitMQ management"},
	9092:  {Broker, 0.55, "Kafka"},
	3000:  {Git, 0.5, "Gitea (domyślny port)"},
	21:    {FileServer, 0.6, "FTP"},
	445:   {Server, 0.5, "SMB"},
	22:    {Server, 0.3, "SSH"},
	80:    {Web, 0.5, "HTTP"},
	443:   {Web, 0.5, "HTTPS"},
	8080:  {Web, 0.5, "HTTP (alt)"},
	8443:  {Web, 0.5, "HTTPS (alt)"},
	3389:  {Workstation, 0.55, "RDP"},
	5900:  {Workstation, 0.55, "VNC"},
	5060:  {Phone, 0.6, "SIP"},
	5061:  {Phone, 0.6, "SIP/TLS"},
}

type bannerRule struct {
	substr string
	class  string
	weight float64
}

// bannerRules match lowercase substrings in service banners and TLS
// certificate subjects. Vendors name themselves there more reliably than
// anywhere else on the wire.
var bannerRules = []bannerRule{
	{"jetdirect", Printer, 0.7}, {"lpd", Printer, 0.6}, {"printer", Printer, 0.6},
	{"ipp", Printer, 0.5}, {"kyocera", Printer, 0.7}, {"ricoh", Printer, 0.7},
	{"hikvision", Camera, 0.8}, {"dahua", Camera, 0.8}, {"axis", Camera, 0.6},
	{"onvif", Camera, 0.7}, {"rtsp", Camera, 0.6}, {"ip camera", Camera, 0.7},
	{"network camera", Camera, 0.7}, {"uc-httpd", Camera, 0.5},
	{"routeros", Network, 0.8}, {"openwrt", Network, 0.8}, {"ubnt", Network, 0.7},
	{"edgeos", Network, 0.7}, {"mikrotik", Network, 0.8},
	{"shelly", IoT, 0.8}, {"tuya", IoT, 0.8}, {"esphome", IoT, 0.8},
	{"esp8266", IoT, 0.7}, {"esp32", IoT, 0.6}, {"mqtt", IoT, 0.5},
	{"grandstream", Phone, 0.8}, {"yealink", Phone, 0.8}, {"asterisk", Phone, 0.6},
	{"openssh", Server, 0.3}, {"dropbear", Server, 0.3},
	{"mysql", Database, 0.6}, {"mariadb", Database, 0.6}, {"postgres", Database, 0.6},
	{"mongodb", Database, 0.6}, {"elasticsearch", Database, 0.6}, {"mssql", Database, 0.6},
	{"redis", Cache, 0.6}, {"memcached", Cache, 0.6},
	{"rabbitmq", Broker, 0.7}, {"amqp", Broker, 0.6}, {"activemq", Broker, 0.7}, {"kafka", Broker, 0.6},
	{"gitea", Git, 0.8}, {"gitlab", Git, 0.8}, {"gogs", Git, 0.8},
	{"vsftpd", FileServer, 0.6}, {"proftpd", FileServer, 0.6}, {"pure-ftpd", FileServer, 0.6},
	{"filezilla", FileServer, 0.6}, {" ftp", FileServer, 0.4},
	{"gunicorn", Web, 0.6}, {"werkzeug", Web, 0.6}, {"flask", Web, 0.6}, {"uvicorn", Web, 0.6},
	{"express", Web, 0.5}, {"tomcat", Web, 0.6}, {"nginx", Web, 0.5}, {"apache", Web, 0.5},
	{"caddy", Web, 0.5}, {"lighttpd", Web, 0.5}, {"node.js", Web, 0.5},
	{"microsoft-iis", Web, 0.5},
}

func containsAny(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func quote(s string) string {
	if len(s) > 48 {
		s = s[:48] + "…"
	}
	return "„" + s + "”"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
