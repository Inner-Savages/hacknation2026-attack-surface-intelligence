package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// VersionMode picks how much time service detection may spend per port.
//
// nmap waits for the full timeout of every probe a service does not answer
// (6 s for a banner, then 5 s or more per probe), and once it knows a port
// speaks HTTP it tries every probe that has ever produced an HTTP answer,
// whatever its intensity. Lowering -sV intensity therefore saves nothing on
// web services and loses others (PostgreSQL). Shorter waits and fewer
// pointless probes do help, so the two faster modes use a probe database
// derived from the installed one at run time.
type VersionMode string

const (
	// VersionBalanced uses the tuned database, then scans the ports it could
	// not identify again with nmap's own waits. The default.
	VersionBalanced VersionMode = "balanced"
	// VersionFast uses the tuned database only.
	VersionFast VersionMode = "fast"
	// VersionFull is plain nmap -sV.
	VersionFull VersionMode = "full"
)

// DefaultVersionWait is how long a probe waits for an answer in the tuned
// database. It must stay well above the round-trip time of the network.
const DefaultVersionWait = 1500 * time.Millisecond

// minVersionWait keeps a typo from turning every service into "unknown".
const minVersionWait = 300 * time.Millisecond

// httpProbes are the probes whose HTTP signatures are kept. The others only
// see HTTP by accident (a web server answering "400 Bad Request" to a TLS,
// SMB or Oracle probe), yet listing http makes nmap send them to every web
// service it has not fully identified.
var httpProbes = map[string]bool{
	"NULL": true, "GenericLines": true, "GetRequest": true,
	"HTTPOptions": true, "RTSPRequest": true, "FourOhFourRequest": true,
}

// TuneProbes rewrites an nmap-service-probes database: TCP probes wait at
// most wait for an answer, and http signatures stay only on probes meant
// for web servers. Everything else is copied unchanged.
func TuneProbes(w io.Writer, r io.Reader, wait time.Duration) error {
	ms := strconv.FormatInt(wait.Milliseconds(), 10)
	out := bufio.NewWriter(w)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	tcp, web, probes := false, false, 0
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "Probe":
			probes++
			tcp, web = f[1] == "TCP", httpProbes[f[2]]
			out.WriteString(line + "\n")
			if tcp {
				out.WriteString("totalwaitms " + ms + "\n")
			}
			continue
		case tcp && len(f) == 2 && f[0] == "totalwaitms":
			continue // replaced above
		case tcp && !web && len(f) >= 2 && (f[0] == "match" || f[0] == "softmatch") && f[1] == "http":
			continue
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if probes == 0 {
		return fmt.Errorf("not an nmap service probe database")
	}
	return out.Flush()
}

// findProbeDB returns the database of the installed nmap, or "".
func findProbeDB(binary string) string {
	const name = "nmap-service-probes"
	var dirs []string
	if d := os.Getenv("NMAPDIR"); d != "" {
		dirs = append(dirs, d)
	}
	if p, err := exec.LookPath(binary); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(p), "..", "share", "nmap"))
	}
	dirs = append(dirs, "/usr/share/nmap", "/usr/local/share/nmap")
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// tunedProbeDB writes the tuned database into a private temporary directory
// and returns its path and a cleanup function. The path is empty when no
// installed database was found; nmap then runs with its own.
func (o Options) tunedProbeDB() (string, func(), error) {
	none := func() {}
	if o.versionMode() == VersionFull {
		return "", none, nil
	}
	src := findProbeDB(o.binary())
	if src == "" {
		return "", none, nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", none, err
	}
	var buf bytes.Buffer
	if err := TuneProbes(&buf, bytes.NewReader(data), o.versionWait()); err != nil {
		return "", none, fmt.Errorf("%s: %w", src, err)
	}
	dir, err := os.MkdirTemp("", "sotw-nmap-")
	if err != nil {
		return "", none, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	path := filepath.Join(dir, "nmap-service-probes")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		cleanup()
		return "", none, err
	}
	return path, cleanup, nil
}
