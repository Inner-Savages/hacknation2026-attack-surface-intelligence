package main

import (
	"context"
	"log"
	"os"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/vuln"
)

// maxVulnsPerTech caps the CVE list attached to one technology: the ranking
// is EPSS-first, so the tail is noise anyway.
const maxVulnsPerTech = 5

// enrichCVE resolves every detected technology with a known version to its
// CPE and attaches the EPSS-ranked CVEs affecting exactly that version.
// Lookups are cached per product, so repeated scans of the same estate cost
// almost no quota; failures degrade to "no vulns" instead of failing the
// scan.
func enrichCVE(ctx context.Context, res *result.Scan, cacheDir string) {
	client, err := vuln.NewClient(cacheDir, os.Getenv("NVD_API_KEY"))
	if err != nil {
		log.Printf("cve: cache unavailable: %v (skipping enrichment)", err)
		return
	}

	// One lookup per unique product+version; the NVD anonymous quota is
	// tight, so unique pairs are resolved sequentially with pacing, then
	// fanned out to every matching tech entry.
	type key struct {
		name, version string
	}
	uniq := map[key]bool{}
	for i := range res.Hosts {
		for j := range res.Hosts[i].Services {
			for _, t := range res.Hosts[i].Services[j].Tech {
				if t.Version != "" {
					uniq[key{t.Name, t.Version}] = true
				}
			}
		}
	}
	ranked := map[key][]result.Vuln{}
	for k := range uniq {
		if ctx.Err() != nil {
			return
		}
		vulns, err := client.EnrichTech(ctx, k.name, k.version)
		if err != nil {
			log.Printf("cve: %s %s: %v", k.name, k.version, err)
			continue
		}
		if len(vulns) > maxVulnsPerTech {
			vulns = vulns[:maxVulnsPerTech]
		}
		if len(vulns) > 0 {
			log.Printf("cve: %s %s -> %d CVEs, top %s (EPSS %.2f)", k.name, k.version, len(vulns), vulns[0].CVE, vulns[0].EPSS)
		}
		ranked[k] = vulns
	}

	for i := range res.Hosts {
		for j := range res.Hosts[i].Services {
			for k := range res.Hosts[i].Services[j].Tech {
				t := &res.Hosts[i].Services[j].Tech[k]
				if vulns, ok := ranked[key{t.Name, t.Version}]; ok {
					t.Vulns = vulns
				}
			}
		}
	}
}
