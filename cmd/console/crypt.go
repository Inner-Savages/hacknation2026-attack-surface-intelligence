package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/Inner-Savages/silence-on-the-wire/internal/atrest"
)

// rest encrypts every durable console file (accounts, sessions' source data,
// settings with API keys, rules, cases/escalations, host registry, audit log)
// with AES-256-GCM. nil means "disabled" (unit tests that do not care) and
// behaves as pass-through, so plaintext stores written by older versions
// remain readable and are encrypted on their next write.
var rest *atrest.Cipher

// initAtRest loads the data key: ASI_DATA_KEY (hex/base64, 32 bytes) wins,
// otherwise <data-dir>/data.key is used and created (0600) on first start.
// For real deployments keep the key off the data volume (env var or a
// separately mounted key file via ASI_DATA_KEY_FILE).
func initAtRest(dataDir string) error {
	keyFile := os.Getenv("ASI_DATA_KEY_FILE")
	if keyFile == "" {
		keyFile = filepath.Join(dataDir, "data.key")
	}
	key, src, err := atrest.LoadKey(os.Getenv("ASI_DATA_KEY"), keyFile)
	if err != nil {
		return err
	}
	c, err := atrest.New(key)
	if err != nil {
		return err
	}
	rest = c
	log.Printf("data at rest: AES-256-GCM enabled (key: %s)", src)
	return nil
}
