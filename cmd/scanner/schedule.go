package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // -tz must work in images without a zone database

	"github.com/Inner-Savages/silence-on-the-wire/internal/pipeline"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
	"github.com/Inner-Savages/silence-on-the-wire/internal/schedule"
)

// runSchedule implements "scanner schedule".
func runSchedule(args []string) {
	fs := flag.NewFlagSet("schedule", flag.ExitOnError)
	sf := addScanFlags(fs)
	var (
		window     = fs.String("window", "", "only scan inside these windows: [days] HH:MM-HH:MM, comma separated, e.g. \"mon-fri 22:00-05:00,sat+sun 00:00-24:00\" (default: always)")
		tz         = fs.String("tz", "", "time zone of -window and -every, e.g. Europe/Warsaw (default: local)")
		every      = fs.String("every", "once", "how often to scan: once, an interval (24h), daily@22:00, mon+thu@22:00, mon-fri@22:00")
		checkpoint = fs.String("checkpoint", "scan-state.jsonl", "file that keeps the progress of the current run")
		outDir     = fs.String("out", ".", "directory for results, written as scan-<start>.json")
	)
	fs.Parse(args)
	if fs.NArg() > 0 {
		log.Fatalf("unexpected argument %q", fs.Arg(0))
	}

	loc := time.Local
	if *tz != "" {
		var err error
		if loc, err = time.LoadLocation(*tz); err != nil {
			log.Fatal(err)
		}
	}
	windows, err := schedule.ParseWindows(*window, loc)
	if err != nil {
		log.Fatal(err)
	}
	freq, err := schedule.ParseFrequency(*every, loc)
	if err != nil {
		log.Fatal(err)
	}
	cfg, targets := sf.config()
	if st, err := os.Stat(*outDir); err != nil {
		log.Fatal(err)
	} else if !st.IsDir() {
		log.Fatalf("%s is not a directory", *outDir)
	}
	store, err := schedule.OpenFileStore(*checkpoint)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	log.Printf("%d targets, %s: nmap %s", targets.Len(), chunking(cfg), strings.Join(cfg.Scanner.Options.Args(), " "))
	cfg.Scanner.Progress = func(p scan.Progress) {
		s := progressLine(p)
		if p.ETA > 0 && !windows.Always() {
			s += ", done by " + windows.Finish(time.Now(), p.ETA).In(loc).Format("2006-01-02 15:04:05")
		}
		log.Print(s)
	}
	r := &schedule.Runner{
		Targets:   targets.Items(),
		Config:    sf.scope(),
		Settings:  cfg.Scanner.Settings(),
		Windows:   windows,
		Frequency: freq,
		Engine:    cfg.ScheduleEngine(),
		Store:     store,
		Logf:      log.Printf,
		OnResult: func(run schedule.Run, res *result.Scan) error {
			path := filepath.Join(*outDir, "scan-"+run.ID+".json")
			if err := writeResultFile(path, res); err != nil {
				return err
			}
			up, open := pipeline.Counts(res)
			log.Printf("run %s done: scanned for %v in %d session(s), %d chunks, %d hosts up, %d open ports -> %s", run.ID,
				time.Duration(res.Duration).Round(time.Millisecond), len(res.Sessions), len(res.Chunks), up, open, path)
			return nil
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := r.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Printf("stopped; run the same command to continue (progress is in %s)", *checkpoint)
			return
		}
		log.Fatal(err)
	}
}
