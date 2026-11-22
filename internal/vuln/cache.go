package vuln

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// cache is a tiny JSON-file cache so repeated scans of the same products
// do not burn the (unauthenticated, tight) quotas of NVD and FIRST.
type cache struct {
	dir string
	ttl map[string]time.Duration // namespace -> TTL
}

type cacheEntry struct {
	Expires time.Time       `json:"expires"`
	Data    json.RawMessage `json:"data"`
}

func newCache(dir string) (*cache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &cache{
		dir: dir,
		ttl: map[string]time.Duration{
			"nvd":  7 * 24 * time.Hour, // CVE lists for a CPE barely move
			"epss": 24 * time.Hour,     // exploitation probabilities move daily
			"kev":  24 * time.Hour,
		},
	}, nil
}

func (c *cache) key(namespace, query string) string {
	sum := sha1.Sum([]byte(namespace + "\x00" + query))
	return filepath.Join(c.dir, namespace+"-"+hex.EncodeToString(sum[:])[:16]+".json")
}

// get returns the cached payload when it is still fresh.
func (c *cache) get(namespace, query string) (json.RawMessage, bool) {
	b, err := os.ReadFile(c.key(namespace, query))
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if json.Unmarshal(b, &e) != nil || time.Now().After(e.Expires) {
		return nil, false
	}
	return e.Data, true
}

func (c *cache) set(namespace, query string, data json.RawMessage) {
	ttl := c.ttl[namespace]
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	e := cacheEntry{Expires: time.Now().Add(ttl), Data: data}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	final := c.key(namespace, query)
	tmp := final + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, final)
	}
}
