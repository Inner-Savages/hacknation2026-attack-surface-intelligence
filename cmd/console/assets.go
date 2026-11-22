package main

// Passive asset inventory (CMDB-from-traffic): the sensor already reports
// MAC addresses, open ports, banners and certificate subjects for every
// host it sees. The console folds those signals through the classify
// package into a device-class label — printer, camera, IoT, server,
// workstation, network gear, phone — and keeps it on the host record, so
// the inventory stays alive as long as the traffic does.
//
// Some classes are inherently suspicious when they appear unannounced: a
// new camera in a server room is either an incident or shadow IT. The
// classifier therefore escalates the first sighting of such a device as an
// ordinary case (one per host, deduplicated), which the rule engine and the
// AI operator triage like any other alert.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	devclass "github.com/Inner-Savages/silence-on-the-wire/internal/classify"
)

// assetAlertClasses are the device classes whose sudden appearance deserves
// a case, with the case score. Servers and workstations are expected in a
// network; cameras, printers, IoT gadgets and phones are not — or at least
// someone should confirm them.
var assetAlertClasses = map[string]float64{
	devclass.Camera:  0.8,
	devclass.Printer: 0.6,
	devclass.Phone:   0.6,
	devclass.IoT:     0.55,
}

// reclassify recomputes the device class of one host from everything the
// passive record knows about it. Returns a snapshot of the record and
// whether the class actually changed. Timeline events are added on the
// first confident classification and on every later change.
func (r *hostRegistry) reclassify(ip string) (snapshot *HostRecord, changed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hosts[ip]
	if !ok {
		return nil, false
	}
	in := devclass.Input{MAC: h.MAC}
	for _, svc := range h.Services {
		in.Ports = append(in.Ports, svc.Port)
		if svc.Banner != "" {
			in.Banners = append(in.Banners, svc.Banner)
		}
	}
	for _, rec := range h.TLS {
		in.TLSSubjects = append(in.TLSSubjects, rec.Subject)
	}
	out := devclass.Classify(in)
	prev := h.Class
	reasons := make([]string, 0, len(out.Reasons))
	for _, ev := range out.Reasons {
		reasons = append(reasons, ev.Source+": "+ev.Detail)
	}
	changed = out.Class != prev
	// Skip the write only when nothing at all moved: same class, vendor,
	// confidence and evidence set. New evidence with an unchanged verdict
	// still refreshes the record (confidence grows, reasons accumulate).
	if !changed && h.ClassifiedAt != nil && out.Vendor == h.ClassVendor &&
		out.Confidence == h.ClassConfidence && strings.Join(reasons, "|") == strings.Join(h.ClassReasons, "|") {
		return nil, false
	}
	now := time.Now()
	h.Class = out.Class
	h.ClassVendor = out.Vendor
	h.ClassConfidence = out.Confidence
	h.ClassReasons = reasons
	h.ClassifiedAt = &now
	if out.Class != devclass.Unknown && (changed || prev == "") {
		detail := out.Class
		if out.Vendor != "" {
			detail += " · " + out.Vendor
		}
		if changed && prev != "" {
			detail = "reklasyfikacja: " + prev + " → " + detail
		}
		r.addEvent(topologyEvent{Time: now, Type: "asset_classified", IP: ip, SensorID: h.SensorID, Detail: detail})
	}
	r.dirty = true
	cp := *h
	return &cp, changed
}

// updateAssetClass is the intake hook: a fresh host_new or service_new
// line means new evidence, so the host's label is recomputed. A confident
// alert-worthy class on a first classification escalates into a case.
func (s *server) updateAssetClass(ip string) {
	if s.gt == nil {
		return
	}
	h, changed := s.gt.registry.reclassify(ip)
	if h == nil || !changed {
		return
	}
	score, alertable := assetAlertClasses[h.Class]
	if !alertable {
		return
	}
	s.escalateAsset(h, score)
}

// escalateAsset opens the "new camera in the server room" case. The event
// ID is stable per host, so a reclassification never duplicates the case —
// deduplication in the store turns repeats into no-ops.
func (s *server) escalateAsset(h *HostRecord, score float64) {
	eventID := assetEventID(h.IP)
	reason := fmt.Sprintf("W sieci sensora %s pojawiło się nowe urządzenie sklasyfikowane jako %s (pewność %.0f%%). ",
		h.SensorID, h.Class, h.ClassConfidence*100)
	if h.ClassVendor != "" {
		reason += "Producent z OUI adresu MAC: " + h.ClassVendor + ". "
	}
	if h.MAC != "" {
		reason += "MAC: " + h.MAC + ". "
	}
	if len(h.ClassReasons) > 0 {
		reason += "Dowody: " + strings.Join(h.ClassReasons, "; ") + ". "
	}
	reason += fmt.Sprintf("Nowa %s w sieci to klasyczny sygnał naruszenia lub shadow IT — wymaga potwierdzenia przez operatora.", h.Class)
	evidence := make([]map[string]string, 0, len(h.ClassReasons))
	for _, rsn := range h.ClassReasons {
		evidence = append(evidence, map[string]string{"reason": rsn})
	}
	event := map[string]interface{}{
		"time": time.Now().UTC().Format(time.RFC3339), "type": "asset_new",
		"ip": h.IP, "class": h.Class, "vendor": h.ClassVendor, "mac": h.MAC,
		"confidence": h.ClassConfidence, "evidence": evidence,
	}
	envelope, _ := json.Marshal(map[string]interface{}{
		"event": event, "event_id": eventID,
		"sensor_id": h.SensorID, "forward": true, "reason": reason,
	})
	c := &Case{
		EventID: eventID, Received: time.Now(), Envelope: envelope,
		SensorID: h.SensorID, EventType: "asset_new",
		EventTime: time.Now().UTC().Format(time.RFC3339),
		Source:    h.IP, Target: "—", Score: score,
		Reason: reason, Status: StatusNew,
	}
	created, err := s.store.AddEscalation(c)
	if err != nil {
		s.feed.Append("alert", h.SensorID, "Zasoby: nie udało się zapisać sprawy dla "+h.IP+": "+err.Error(), nil)
		return
	}
	if created {
		s.feed.Append("alert", h.SensorID,
			fmt.Sprintf("Zasoby: nowe urządzenie klasy %s w sieci — %s (sprawa %s)", h.Class, h.IP, eventID), nil)
		// Route the fresh case through the active triage path like any
		// other escalation (rules or AI operator).
		s.triageNewCase(h.SensorID, eventID)
	}
}

// assets serves the passive inventory: every known host with its device
// class, vendor and evidence, plus per-class counters. ?class=<klasa>
// filters the listing.
func (s *server) assets(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{"hosts": []*HostRecord{}, "classes": map[string]int{}}
	if s.gt == nil {
		writeJSON(w, 200, out)
		return
	}
	want := r.URL.Query().Get("class")
	hosts := s.gt.registry.hostsSnapshot()
	filtered := []*HostRecord{}
	classes := map[string]int{}
	for _, h := range hosts {
		cls := h.Class
		if cls == "" {
			cls = devclass.Unknown
		}
		classes[cls]++
		if want == "" || cls == want {
			filtered = append(filtered, h)
		}
	}
	out["hosts"] = filtered
	out["classes"] = classes
	out["total"] = len(hosts)
	writeJSON(w, 200, out)
}

// assetDetail serves one host's full record — used by the inventory tab to
// show the evidence behind a label.
func (s *server) assetDetail(w http.ResponseWriter, r *http.Request) {
	if s.gt == nil {
		http.Error(w, "asset inventory unavailable", 503)
		return
	}
	ip := r.PathValue("ip")
	for _, h := range s.gt.registry.hostsSnapshot() {
		if h.IP == ip {
			writeJSON(w, 200, h)
			return
		}
	}
	http.Error(w, "not found", 404)
}

// assetEventID is the stable case ID for the first alert-worthy
// classification of a host.
func assetEventID(ip string) string {
	return "asset-" + strings.ReplaceAll(ip, ".", "-")
}
