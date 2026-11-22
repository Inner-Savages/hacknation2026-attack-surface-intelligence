package pipeline

import (
	"context"
	"errors"

	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
	"github.com/Inner-Savages/silence-on-the-wire/internal/schedule"
)

// ScheduleEngine returns the pipeline as the engine of a schedule.Runner.
func (c *Config) ScheduleEngine() schedule.Engine { return engine{c} }

type engine struct{ c *Config }

func (e engine) Scan(ctx context.Context, j schedule.Job, report func(schedule.Update)) error {
	var t scan.Targets
	for _, s := range j.Targets {
		if err := t.Add(s); err != nil {
			return err
		}
	}
	cfg := *e.c
	cfg.Scanner.Deadline, cfg.Scanner.Speed, cfg.Scanner.Shrink = j.Deadline, j.Speed, j.Fruitless
	progress := cfg.Scanner.Progress
	cfg.Scanner.Progress = func(p scan.Progress) {
		report(schedule.Update{
			Record: schedule.Record{Chunk: p.Chunk, Targets: p.Targets, Hosts: p.Hosts},
			ETA:    p.ETA,
		})
		if progress != nil {
			progress(p)
		}
	}
	_, err := cfg.Run(ctx, &t)
	if errors.Is(err, scan.ErrDeadline) {
		return nil
	}
	return err
}
