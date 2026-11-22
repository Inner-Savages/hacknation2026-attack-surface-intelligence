package main

// Target entry and import: a manual-add form endpoint, file import of target
// lists (txt/CSV/JSON) and import of finished scan results (the JSON of
// internal/result, or the CSV written by internal/export). Everything lands in
// the inventory, where scan data is diffed against the previous result.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/export"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// guard is the single permission hook for the target/import/override API.
// Today it is a plain session check; when RBAC lands, swap the body for the
// permission check (e.g. "targets.write") without touching the routes.
func (s *server) guard(perm string, h http.HandlerFunc) http.Handler {
	_ = perm
	return s.needAuth(h)
}

func (s *server) registerInventoryRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/inventory", s.guard("targets.read", s.inventoryList))
	mux.Handle("GET /api/inventory/diff", s.guard("targets.read", s.inventoryDiff))
	mux.Handle("GET /api/imports", s.guard("targets.read", s.importLog))
	mux.Handle("GET /api/targets", s.guard("targets.read", s.targetsList))
	mux.Handle("GET /api/targets.txt", s.guard("targets.read", s.targetsText))
	mux.Handle("POST /api/targets", s.guard("targets.write", s.targetsAdd))
	mux.Handle("DELETE /api/targets/{value}", s.guard("targets.write", s.targetsDelete))
	mux.Handle("POST /api/import", s.guard("targets.write", s.importHandler))
	mux.Handle("GET /api/overrides", s.guard("targets.read", s.listOverrides))
	mux.Handle("GET /api/overrides/{key}", s.guard("targets.read", s.getOverride))
	mux.Handle("PUT /api/overrides/{key}", s.guard("targets.write", s.putOverride))
	mux.Handle("DELETE /api/overrides/{key}", s.guard("targets.write", s.deleteOverrideH))
}

// --- parsing ---------------------------------------------------------------

type rawTarget struct {
	Value string
	Tags  []string
}

const maxProblems = 20

type problems []string

func (p *problems) add(format string, a ...interface{}) {
	if len(*p) < maxProblems {
		*p = append(*p, fmt.Sprintf(format, a...))
	}
}

func detectFormat(data []byte, want string) string {
	if want != "" && want != "auto" {
		return strings.ToLower(want)
	}
	t := bytes.TrimSpace(data)
	switch {
	case len(t) > 0 && (t[0] == '{' || t[0] == '['):
		return "json"
	case len(t) > 0:
		first := string(bytes.SplitN(t, []byte("\n"), 2)[0])
		if strings.Contains(first, ",") && !strings.Contains(first, "#") {
			return "csv"
		}
	}
	return "txt"
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '|' || r == ',' })
}

// unsafeCell undoes the formula-injection guard of the CSV exporter.
func unsafeCell(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@", rune(s[1])) {
		return s[1:]
	}
	return s
}

func parseTargetFile(data []byte, format string, bad *problems) ([]rawTarget, string, error) {
	format = detectFormat(data, format)
	var out []rawTarget
	switch format {
	case "txt":
		for n, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
				out = append(out, rawTarget{Value: f})
			}
			_ = n
		}
	case "csv":
		rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
		if err != nil {
			return nil, format, fmt.Errorf("csv: %v", err)
		}
		valCol, tagCol, start := 0, -1, 0
		if len(rows) > 0 {
			for i, h := range rows[0] {
				switch strings.ToLower(strings.TrimSpace(h)) {
				case "target", "value", "address", "host", "hostname", "ip", "cidr", "domain":
					valCol, start = i, 1
				case "tags", "tag":
					tagCol, start = i, 1
				}
			}
		}
		for _, row := range rows[start:] {
			if len(row) <= valCol {
				continue
			}
			rt := rawTarget{Value: unsafeCell(row[valCol])}
			if tagCol >= 0 && tagCol < len(row) {
				rt.Tags = splitList(row[tagCol])
			}
			out = append(out, rt)
		}
	case "json":
		var anyv interface{}
		if err := json.Unmarshal(data, &anyv); err != nil {
			return nil, format, fmt.Errorf("json: %v", err)
		}
		if m, ok := anyv.(map[string]interface{}); ok {
			anyv = m["targets"]
		}
		list, ok := anyv.([]interface{})
		if !ok {
			return nil, format, errors.New(`json: expected an array or {"targets": [...]}`)
		}
		for i, it := range list {
			switch v := it.(type) {
			case string:
				out = append(out, rawTarget{Value: v})
			case map[string]interface{}:
				rt := rawTarget{}
				for _, k := range []string{"value", "target", "address"} {
					if s, ok := v[k].(string); ok {
						rt.Value = s
						break
					}
				}
				if ts, ok := v["tags"].([]interface{}); ok {
					for _, t := range ts {
						if s, ok := t.(string); ok {
							rt.Tags = append(rt.Tags, s)
						}
					}
				} else if s, ok := v["tags"].(string); ok {
					rt.Tags = splitList(s)
				}
				out = append(out, rt)
			default:
				bad.add("item %d: expected string or object", i+1)
			}
		}
	default:
		return nil, format, fmt.Errorf("unknown format %q (txt, csv, json)", format)
	}
	return out, format, nil
}

func hasTargetKind(kind string) bool { return kind == "targets" || kind == "scan" }

func parseScanFile(data []byte, format string, bad *problems) (*result.Scan, string, error) {
	format = detectFormat(data, format)
	switch format {
	case "json":
		var sc result.Scan
		dec := json.NewDecoder(bytes.NewReader(data))
		if err := dec.Decode(&sc); err != nil {
			return nil, format, fmt.Errorf("json: %v", err)
		}
		if len(sc.Hosts) == 0 {
			return nil, format, errors.New("scan has no hosts")
		}
		if len(sc.Hosts) > maxScanHosts {
			return nil, format, fmt.Errorf("scan has %d hosts, limit is %d", len(sc.Hosts), maxScanHosts)
		}
		if err := validateScan(&sc, bad); err != nil {
			return nil, format, err
		}
		return &sc, format, nil
	case "csv":
		sc, err := scanFromCSV(data, bad)
		return sc, format, err
	}
	return nil, format, fmt.Errorf("scan import accepts json or csv, not %q", format)
}

// validateScan normalizes addresses and drops duplicate or malformed
// services. Malformed hosts reject the file: a scan is machine output, so
// garbage means the wrong file.
func validateScan(sc *result.Scan, bad *problems) error {
	seenHost := map[string]int{}
	var hosts []result.Host
	for i := range sc.Hosts {
		h := sc.Hosts[i]
		v, _, err := normalizeTarget(h.Address)
		if err != nil || strings.Contains(h.Address, "/") {
			return fmt.Errorf("host %d: invalid address %q", i+1, h.Address)
		}
		h.Address = v
		if h.State == "" {
			h.State = "up"
		}
		seenSvc := map[string]bool{}
		var svcs []result.Service
		for _, s := range h.Services {
			k := s.Proto + "/" + strconv.Itoa(s.Port)
			if s.Port < 1 || s.Port > 65535 || (s.Proto != "tcp" && s.Proto != "udp" && s.Proto != "sctp") {
				bad.add("%s: invalid service %s", h.Address, k)
				continue
			}
			if seenSvc[k] {
				bad.add("%s: duplicate service %s", h.Address, k)
				continue
			}
			seenSvc[k] = true
			svcs = append(svcs, s)
		}
		h.Services = svcs
		if j, dup := seenHost[h.Address]; dup {
			hosts[j].Services = append(hosts[j].Services, h.Services...)
			bad.add("duplicate host %s merged", h.Address)
			continue
		}
		seenHost[h.Address] = len(hosts)
		hosts = append(hosts, h)
	}
	sc.Hosts = hosts
	if sc.StartedAt.IsZero() {
		sc.StartedAt = time.Now().UTC()
	}
	return nil
}

func scanFromCSV(data []byte, bad *problems) (*result.Scan, error) {
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("csv: %v", err)
	}
	if len(rows) < 2 {
		return nil, errors.New("csv: header and at least one row required")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, need := range []string{"address", "port"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("csv: missing column %q (expected the export.ScanColumns header: %s)", need, strings.Join(export.ScanColumns, ","))
		}
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return unsafeCell(strings.TrimSpace(row[i]))
		}
		return ""
	}
	if len(rows)-1 > maxScanHosts*10 {
		return nil, errors.New("csv: too many rows")
	}
	sc := &result.Scan{StartedAt: time.Now().UTC()}
	idx := map[string]int{}
	seen := map[string]bool{}
	for n, row := range rows[1:] {
		line := n + 2
		addr, _, err := normalizeTarget(get(row, "address"))
		port, perr := strconv.Atoi(get(row, "port"))
		proto := strings.ToLower(get(row, "proto"))
		if proto == "" {
			proto = "tcp"
		}
		if err != nil || perr != nil || port < 1 || port > 65535 || (proto != "tcp" && proto != "udp" && proto != "sctp") {
			bad.add("line %d: invalid address/port/proto", line)
			continue
		}
		k := svcKey(addr, proto, port)
		if seen[k] {
			bad.add("line %d: duplicate %s", line, k)
			continue
		}
		seen[k] = true
		hi, ok := idx[addr]
		if !ok {
			if len(sc.Hosts) >= maxScanHosts {
				return nil, fmt.Errorf("csv: more than %d hosts", maxScanHosts)
			}
			h := result.Host{Address: addr, State: "up"}
			for _, n := range splitList(get(row, "hostnames")) {
				h.Hostnames = append(h.Hostnames, strings.TrimSpace(n))
			}
			sc.Hosts = append(sc.Hosts, h)
			hi = len(sc.Hosts) - 1
			idx[addr] = hi
			sc.Targets = append(sc.Targets, addr)
		}
		svc := result.Service{
			Port: port, Proto: proto, State: "open", Name: get(row, "service"),
			Product: get(row, "product"), Version: get(row, "version"),
		}
		var tags []string
		for _, t := range splitList(get(row, "tags")) {
			tags = append(tags, strings.TrimSpace(t))
		}
		for _, t := range splitList(get(row, "technologies")) {
			name, ver := strings.TrimSpace(t), ""
			if i := strings.LastIndexByte(name, ' '); i > 0 && name[i+1:] != "" && name[i+1] >= '0' && name[i+1] <= '9' {
				name, ver = name[:i], name[i+1:]
			}
			if name != "" {
				svc.Tech = append(svc.Tech, result.Tech{Name: name, Version: ver, Confidence: 1, Tags: tags, Evidence: []string{"csv import"}})
			}
		}
		st, _ := strconv.Atoi(get(row, "http_status"))
		if title := get(row, "http_title"); title != "" || st != 0 {
			svc.HTTP = &result.HTTP{Status: st, Title: title}
		}
		sc.Hosts[hi].Services = append(sc.Hosts[hi].Services, svc)
	}
	if len(sc.Hosts) == 0 {
		return nil, errors.New("csv: no valid rows")
	}
	return sc, nil
}

// --- handlers --------------------------------------------------------------

// readUpload returns the file body of a multipart "file" field or the raw
// request body, limited to maxImportBytes.
func readUpload(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes+(64<<10))
	name := r.URL.Query().Get("source")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		f, hdr, err := r.FormFile("file")
		if err != nil {
			return nil, "", fmt.Errorf("multipart field \"file\": %v", err)
		}
		defer f.Close()
		if name == "" {
			name = hdr.Filename
		}
		b, err := io.ReadAll(io.LimitReader(f, maxImportBytes+1))
		if err == nil && len(b) > maxImportBytes {
			err = errTooLarge
		}
		return b, name, err
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxImportBytes+1))
	if err == nil && len(b) > maxImportBytes {
		err = errTooLarge
	}
	return b, name, err
}

var errTooLarge = errors.New("file larger than 5 MiB")

func uploadStatus(err error) int {
	var mb *http.MaxBytesError
	if errors.Is(err, errTooLarge) || errors.As(err, &mb) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func safeSource(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	if len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		name = "upload"
	}
	return name
}

func (s *server) importHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := q.Get("kind")
	if !hasTargetKind(kind) {
		http.Error(w, "kind must be targets or scan", 400)
		return
	}
	data, name, err := readUpload(w, r)
	if err != nil {
		http.Error(w, err.Error(), uploadStatus(err))
		return
	}
	if len(bytes.TrimSpace(data)) == 0 {
		http.Error(w, "empty file", 400)
		return
	}
	source, actor := safeSource(name), s.actor(r, nil)
	var bad problems
	rec := ImportRecord{At: time.Now().UTC(), Actor: actor, Kind: kind, Source: source}

	if kind == "scan" {
		sc, format, err := parseScanFile(data, q.Get("format"), &bad)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rec.Format, rec.Accepted, rec.Rejected = format, len(sc.Hosts), len(bad)
		d, err := s.inv.ingestScan(sc, rec)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		services := 0
		for _, h := range sc.Hosts {
			services += len(h.Services)
		}
		writeJSON(w, 200, map[string]interface{}{
			"kind": kind, "format": format, "hosts": len(sc.Hosts), "services": services,
			"problems": bad, "diff": d,
		})
		return
	}

	raw, format, err := parseTargetFile(data, q.Get("format"), &bad)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	extra := cleanTags(splitList(q.Get("tags")))
	var ts []Target
	seen := map[string]bool{}
	filedups := 0
	for i, rt := range raw {
		v, k, err := normalizeTarget(rt.Value)
		if err != nil {
			bad.add("entry %d: %v", i+1, err)
			rec.Rejected++
			continue
		}
		if seen[v] {
			filedups++
			continue
		}
		seen[v] = true
		ts = append(ts, Target{Value: v, Kind: k, Tags: cleanTags(append(rt.Tags, extra...)), Source: "import:" + source, Actor: actor, Added: time.Now().UTC()})
	}
	if len(ts) == 0 {
		http.Error(w, "no valid targets: "+strings.Join(bad, "; "), 400)
		return
	}
	added, dups, err := s.inv.addTargets(ts)
	rec.Format, rec.Accepted, rec.Duplicates = format, added, dups+filedups
	s.inv.mu.Lock()
	s.inv.record(rec)
	s.inv.saveLocked()
	s.inv.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 507)
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"kind": kind, "format": format, "added": added, "duplicates": dups + filedups,
		"rejected": rec.Rejected, "problems": bad,
	})
}

func (s *server) targetsAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value string   `json:"value"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), 400)
		return
	}
	v, k, err := normalizeTarget(body.Value)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	t := Target{Value: v, Kind: k, Tags: cleanTags(body.Tags), Source: "manual", Actor: s.actor(r, nil), Added: time.Now().UTC()}
	added, _, err := s.inv.addTargets([]Target{t})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	code := 201
	if added == 0 {
		code = 200 // already known; tags merged
	}
	writeJSON(w, code, map[string]interface{}{"value": v, "kind": k, "added": added == 1})
}

func (s *server) targetsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.inv.listTargets())
}

// targetsText is the target list in the format `scanner -f` reads.
func (s *server) targetsText(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, t := range s.inv.listTargets() {
		fmt.Fprintln(w, t.Value)
	}
}

func (s *server) targetsDelete(w http.ResponseWriter, r *http.Request) {
	ok, err := s.inv.deleteTarget(r.PathValue("value"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !ok {
		http.Error(w, "unknown target", 404)
		return
	}
	w.WriteHeader(204)
}

func (s *server) inventoryList(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	status := r.URL.Query().Get("status")
	all := s.inv.entries()
	out := make([]Entry, 0, len(all))
	for _, e := range all {
		if status != "" && e.Effective.Status != status {
			continue
		}
		if q != "" {
			hay := strings.ToLower(e.Address + " " + e.Effective.Title + " " + e.Effective.Technology + " " + strings.Join(e.Effective.Tags, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, e)
	}
	total := len(out)
	if len(out) > 2000 {
		out = out[:2000]
	}
	s.inv.mu.Lock()
	overrides, targets := len(s.inv.st.Overrides), len(s.inv.st.Targets)
	d := s.inv.st.LastDiff
	s.inv.mu.Unlock()
	resp := map[string]interface{}{"entries": out, "total": total, "targets": targets, "overrides": overrides}
	if d != nil {
		resp["diff_summary"] = d.Summary
	}
	writeJSON(w, 200, resp)
}

func (s *server) inventoryDiff(w http.ResponseWriter, r *http.Request) {
	s.inv.mu.Lock()
	d := s.inv.st.LastDiff
	s.inv.mu.Unlock()
	if d == nil {
		http.Error(w, "no previous scan to compare with", 404)
		return
	}
	writeJSON(w, 200, d)
}

func (s *server) importLog(w http.ResponseWriter, r *http.Request) {
	s.inv.mu.Lock()
	defer s.inv.mu.Unlock()
	writeJSON(w, 200, s.inv.st.Imports)
}
