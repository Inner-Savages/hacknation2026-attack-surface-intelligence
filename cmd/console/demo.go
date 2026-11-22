package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// Demo seeding proves the console scales to a fleet of hundreds of sensors.
// All records are synthetic and marked as demo data in the UI.

var demoCities = []string{"warszawa", "krakow", "gdansk", "poznan", "wroclaw", "lodz", "katowice", "lublin"}

var demoTypes = []string{"service_changed", "service_new", "host_new", "host_silent", "service_silent", "host_back", "service_closed"}

var demoReasons = []string{"remote_rank_max", "fast_tree_gnb", "model_error", "timeout", "unexpected_model_identity", "fail_open_invalid_event"}

var demoPeople = []string{"M. Kowalska", "A. Lis", "J. Nowak", "P. Zieliński"}

// seedDemo populates an empty store with a fleet of sensors and a realistic
// spread of cases across statuses, sensors and event types.
func seedDemo(s *Store, fleetSize int) {
	rng := rand.New(rand.NewSource(20261122))
	now := time.Now()
	sensors := make([]string, 0, fleetSize)
	for i := 0; i < fleetSize; i++ {
		city := demoCities[i%len(demoCities)]
		id := fmt.Sprintf("edge-%s-%d", city, i/len(demoCities)+1)
		sensors = append(sensors, id)
		// ~92% of the fleet is online; offline sensors last heard from hours ago.
		online := rng.Float64() < 0.92
		last := now.Add(-time.Duration(rng.Intn(50)) * time.Second)
		if !online {
			last = now.Add(-time.Duration(2+rng.Intn(20)) * time.Hour)
		}
		s.RegisterSensor(id, last, online)
	}
	statuses := []string{StatusNew, StatusNew, StatusVerify, StatusVerify, StatusVerify, StatusConfirmed, StatusFalseAlarm, StatusClosed, StatusClosed, StatusClosed}
	for i := 0; i < 3*len(sensors)/2+12; i++ {
		sensor := sensors[rng.Intn(len(sensors))]
		typ := demoTypes[rng.Intn(len(demoTypes))]
		score := 0.3 + rng.Float64()*0.68
		status := statuses[rng.Intn(len(statuses))]
		at := now.Add(-time.Duration(rng.Intn(60*26)) * time.Minute)
		ip := fmt.Sprintf("10.%d.%d.%d", rng.Intn(5), rng.Intn(255), 2+rng.Intn(250))
		port := []int{22, 80, 443, 445, 3389, 5900, 8080, 2375}[rng.Intn(8)]
		reason := demoReasons[rng.Intn(len(demoReasons))]
		unresolved := reason == "model_error" || reason == "timeout" || reason == "fail_open_invalid_event"
		env := demoEnvelope(sensor, typ, ip, port, score, reason, unresolved, at)
		raw, _ := json.Marshal(env)
		c := &Case{
			EventID: fmt.Sprintf("demo-%s-%04d", sensor, i), Received: at, Envelope: raw,
			SensorID: sensor, EventType: typ, EventTime: at.Format(time.RFC3339),
			Source: ip, Target: fmt.Sprintf("172.16.%d.%d:%d", rng.Intn(3), rng.Intn(250), port),
			Score: score, Unresolved: unresolved, Reason: reason, Status: status,
		}
		if status != StatusNew && rng.Float64() < 0.7 {
			c.Assignee = demoPeople[rng.Intn(len(demoPeople))]
		}
		s.AddEscalation(c)
		if rng.Float64() < 0.3 {
			s.mutate(c.EventID, func(c *Case) (HistoryEntry, error) {
				who := demoPeople[rng.Intn(len(demoPeople))]
				text := []string{
					"Sprawdzam na miejscu, host wygląda na kontroler automatyki",
					"Znany serwer druku, do potwierdzenia z właścicielem",
					"Zmiana fingerprintu po aktualizacji firmware",
				}[rng.Intn(3)]
				c.Notes = append(c.Notes, Note{At: at.Add(7 * time.Minute), Actor: who, Text: text})
				return HistoryEntry{At: at.Add(7 * time.Minute), Kind: "note", Actor: who, Text: "Notatka: " + text}, nil
			})
		}
	}
}

func demoEnvelope(sensor, typ, ip string, port int, score float64, reason string, unresolved bool, at time.Time) map[string]interface{} {
	features := make([]float64, 28)
	features[22] = 1
	rng := rand.New(rand.NewSource(int64(port) + at.Unix()))
	for i := range features {
		if rng.Float64() < 0.2 {
			features[i] = float64(rng.Intn(4))
		}
	}
	fast := map[string]interface{}{"forward": false, "stage": "fast", "reason": "below_fast_threshold", "threshold": 0.5152814464395828}
	remote := map[string]interface{}{"forward": !unresolved, "unresolved": unresolved, "stage": "remote", "reason": reason, "score": score, "threshold": 0.8998301933678775}
	return map[string]interface{}{
		"event": map[string]interface{}{
			"time": at.Format(time.RFC3339), "type": typ, "ip": ip, "port": port, "proto": "tcp",
			"new": "OpenSSH_9.6", "old": "OpenSSH_9.3", "banner": "SSH-2.0-OpenSSH_9.6",
		},
		"event_id": fmt.Sprintf("demo-%s", sensor), "sensor_id": sensor,
		"forward": true, "unresolved": unresolved, "reason": reason, "model": "tree+gnb+rankmax",
		"policy_sha256":     "ea8044022817e99fd2916cbd10e8849904b0264a0dfc77bb702b7972d3589dee",
		"validation_budget": 0.5, "baseline_anomaly": 0.42,
		"features": features, "fast_decision": fast, "remote_decision": remote,
		"systemone_scores": map[string]interface{}{
			"basal": map[string]interface{}{"score": score - 0.03, "reported_model": "basal-omni-pico 2.8.1", "latency_ms": 34},
			"laya":  map[string]interface{}{"score": score - 0.05, "reported_model": "laya-english 0.5.2", "latency_ms": 51},
			"kev":   map[string]interface{}{"score": score, "reported_model": "Kev-0.8B", "latency_ms": 47},
		},
		"systemone_errors": map[string]string{},
	}
}
