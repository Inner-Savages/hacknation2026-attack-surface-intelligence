// edgegate consumes the passive sensor's JSONL without changing the sensor.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edgegate {serve|gate|check-models|fetch-models|verify-models|replay|receive} [flags]")
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		o := serveOptions{}
		fs.StringVar(&o.Listen, "listen", "127.0.0.1:8098", "address for POST /events (sensor webhook) and GET /healthz")
		fs.StringVar(&o.TriggerURL, "trigger-url", "http://127.0.0.1:8099/events", "where forwarded events go (the trigger's /events)")
		fs.StringVar(&o.Token, "token", os.Getenv("SOTW_WEBHOOK_TOKEN"), "bearer token required from senders and sent to the trigger (default $SOTW_WEBHOOK_TOKEN)")
		fs.StringVar(&o.Policy, "policy", "deploy/cascade50/policy.json", "calibrated policy bundle")
		fs.StringVar(&o.Sensor, "sensor-id", "sensor", "sensor id for events without a \"sensor\" field")
		fs.StringVar(&o.Outbox, "outbox-dir", "var/cascade50/serve-outbox", "durable events waiting for the trigger")
		fs.DurationVar(&o.Timeout, "model-timeout", 6*time.Second, "timeout per parallel model request")
		fs.IntVar(&o.Queue, "queue", 4096, "events accepted but not yet scored; beyond this senders get 503 and retry")
		basal := fs.String("basal-url", "http://127.0.0.1:18000/v1/systemone", "Basal endpoint")
		laya := fs.String("laya-url", "http://127.0.0.1:18001/v1/systemone", "Laya endpoint")
		kev := fs.String("kev-url", "http://127.0.0.1:18008/v1/systemone", "Kev endpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		o.URLs = map[string]string{"basal": *basal, "laya": *laya, "kev": *kev}
		return serve(o)
	case "gate", "check-models":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		o := cascadeGateOptions{URLs: map[string]string{}}
		fs.StringVar(&o.Policy, "policy", "deploy/cascade50/policy.json", "calibrated policy bundle")
		fs.StringVar(&o.Sensor, "sensor-id", "", "stable sensor identifier (required for gate)")
		fs.StringVar(&o.Input, "input", "", "sensor JSONL file (default stdin)")
		fs.StringVar(&o.Outbox, "outbox-dir", "var/cascade50/outbox", "durable pending escalations")
		fs.StringVar(&o.Central, "central-url", "", "POST escalations here; empty keeps them in outbox")
		fs.BoolVar(&o.Follow, "follow", false, "follow an append-only input file from the beginning")
		fs.DurationVar(&o.Timeout, "model-timeout", 6*time.Second, "timeout per parallel model request")
		basal := fs.String("basal-url", "http://127.0.0.1:18000/v1/systemone", "Basal endpoint")
		laya := fs.String("laya-url", "http://127.0.0.1:18001/v1/systemone", "Laya endpoint")
		kev := fs.String("kev-url", "http://127.0.0.1:18008/v1/systemone", "Kev endpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected positional arguments")
		}
		o.URLs = map[string]string{"basal": *basal, "laya": *laya, "kev": *kev}
		if args[0] == "gate" {
			return cascadeGate(o)
		}
		p, id, err := loadCascadePolicy(o.Policy)
		if err != nil {
			return err
		}
		g, err := newCascadeEngine(p, id, o.URLs, o.Timeout)
		if err != nil {
			return err
		}
		e := aiml.Event{Time: "2026-11-21T00:00:00Z", Type: "host_new", IP: "192.0.2.1", Source: "passive"}
		x := aiml.NewExtractor().Features(e)
		for _, name := range p.Cascade.Remote {
			mc := g.clients[name]
			score, err := mc.backend.Predict(mc.client, e, x, p.Baseline.Anomaly(e))
			if err != nil {
				return fmt.Errorf("%s readiness: %w", name, err)
			}
			log.Printf("%s ready: model=%s latency=%.1fms", name, score.ReportedModel, score.LatencyMS)
		}
		return nil
	case "fetch-models":
		fs := flag.NewFlagSet("fetch-models", flag.ContinueOnError)
		manifest := fs.String("manifest", "models/manifest.json", "artifact manifest; paths relative to its directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return fetchModels(*manifest, "huggingface.co", modelClient())
	case "verify-models":
		fs := flag.NewFlagSet("verify-models", flag.ContinueOnError)
		manifest := fs.String("manifest", "models/manifest.json", "artifact manifest; paths relative to its directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return verifyModels(*manifest)
	case "replay":
		fs := flag.NewFlagSet("replay", flag.ContinueOnError)
		dir := fs.String("outbox-dir", "var/cascade50/outbox", "pending escalation directory")
		url := fs.String("central-url", "", "destination (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := validateRemote(*url); err != nil {
			return err
		}
		q, err := openCascadeOutbox(*dir)
		if err != nil {
			return err
		}
		n, err := q.deliver(cascadeCentralClient(), *url)
		log.Printf("acknowledged %d pending escalations", n)
		return err
	case "receive":
		return receive(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
