// Command scanner runs a safe discovery scan (nmap -sT/-sS -sV, no NSE
// scripts) over IPs, CIDRs and hostnames, split into parallel chunks, probes
// the web services it finds and writes the result as JSON.
//
//	scanner -t 127.0.0.1 -p 2223,3001,5673,8787,8888,15432,15673 -Pn -o scan.json
//	scanner -f targets.txt -allow 10.0.0.0/16 -max-rate 300
//	scanner diff old.json new.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/pipeline"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("scanner: ")
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "diff":
			runDiff(os.Args[2:])
			return
		}
	}
	sf := addScanFlags(flag.CommandLine)
	output := flag.String("o", "", "write the JSON result here (default or \"-\": stdout)")
	flag.Parse()
	cfg, targets := sf.config()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("%d targets, %s: nmap %s", targets.Len(), chunking(cfg), strings.Join(cfg.Scanner.Options.Args(), " "))
	res, err := cfg.Run(ctx, targets)
	if res == nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Printf("scan interrupted: %v (writing partial result)", err)
	}
	if *output == "" || *output == "-" {
		err = writeResult(os.Stdout, res)
	} else {
		err = writeResultFile(*output, res)
	}
	if err != nil {
		log.Fatal(err)
	}
	up, open := pipeline.Counts(res)
	log.Printf("done in %v: %d hosts up, %d open ports", time.Duration(res.Duration).Round(time.Millisecond), up, open)
}

func writeResult(w io.Writer, res *result.Scan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func writeResultFile(path string, res *result.Scan) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(writeResult(f, res), f.Close())
}

// chunking describes how targets are split, for the log.
func chunking(cfg *pipeline.Config) string {
	set := cfg.Scanner.Settings()
	if set.ChunkTarget == 0 {
		return fmt.Sprintf("chunks of %d, %d in parallel", set.ChunkSize, set.Parallel)
	}
	return fmt.Sprintf("chunks of about %v (first %d targets), %d in parallel", time.Duration(set.ChunkTarget), set.ChunkSize, set.Parallel)
}
