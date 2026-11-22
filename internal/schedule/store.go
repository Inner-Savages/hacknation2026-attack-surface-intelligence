package schedule

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Run identifies one run of a scheduled scan, possibly spread over several
// windows.
type Run struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"` // hash of targets and settings; see RunKey
	StartedAt time.Time `json:"started_at"`
	Targets   int       `json:"targets"`
}

// Record is a finished chunk: what was covered and what was found.
type Record struct {
	Chunk   result.Chunk  `json:"chunk"`
	Targets []string      `json:"targets"`
	Hosts   []result.Host `json:"hosts,omitempty"`
}

// Checkpoint is the stored state of a run.
type Checkpoint struct {
	Run        Run
	Records    []Record
	Sessions   []result.Session
	FinishedAt time.Time // zero while the run is unfinished
}

// Store keeps the latest run of one scheduled scan. Runner never calls it
// concurrently. Records and sessions must be durable when the call returns:
// whatever is lost gets scanned again.
type Store interface {
	// Load returns the latest run, or nil if there is none.
	Load(ctx context.Context) (*Checkpoint, error)
	// Begin starts a new run, replacing the previous one.
	Begin(ctx context.Context, r Run) error
	// SaveRecord adds a finished chunk to the current run.
	SaveRecord(ctx context.Context, r Record) error
	// SaveSession adds a finished session to the current run.
	SaveSession(ctx context.Context, s result.Session) error
	// Finish marks the current run as completed.
	Finish(ctx context.Context, at time.Time) error
}

// line is one line of the checkpoint file; exactly one field is set.
type line struct {
	Run      *Run            `json:"run,omitempty"`
	Record   *Record         `json:"record,omitempty"`
	Session  *result.Session `json:"session,omitempty"`
	Finished *time.Time      `json:"finished,omitempty"`
}

// FileStore keeps the checkpoint as JSON lines: the run first, then finished
// chunks and sessions as they come. Appending keeps the cost of a checkpoint
// independent of the scan size, and a line torn by a crash is dropped.
type FileStore struct {
	path string
	lock *os.File
	mu   sync.Mutex
}

// OpenFileStore opens (or prepares to create) a checkpoint file and locks
// it, so two schedulers cannot share it by mistake.
func OpenFileStore(path string) (*FileStore, error) {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("checkpoint %s is in use by another scheduler: %w", path, err)
	}
	return &FileStore{path: path, lock: lock}, nil
}

// Close releases the lock.
func (s *FileStore) Close() error { return s.lock.Close() }

// Load implements Store.
func (s *FileStore) Load(context.Context) (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cp *Checkpoint
	var good int64 // bytes of complete, valid lines
	r := bufio.NewReader(f)
	for n := 1; ; n++ {
		raw, err := r.ReadBytes('\n')
		if err == io.EOF {
			break // an unterminated last line is torn: ignore it
		}
		if err != nil {
			return nil, err
		}
		var l line
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, fmt.Errorf("checkpoint %s line %d: %w", s.path, n, err)
		}
		if n == 1 && l.Run == nil {
			return nil, fmt.Errorf("checkpoint %s does not start with a run: not a checkpoint file?", s.path)
		}
		switch {
		case l.Run != nil:
			cp = &Checkpoint{Run: *l.Run}
		case l.Record != nil:
			cp.Records = append(cp.Records, *l.Record)
		case l.Session != nil:
			cp.Sessions = append(cp.Sessions, *l.Session)
		case l.Finished != nil:
			cp.FinishedAt = *l.Finished
		}
		good += int64(len(raw))
	}
	if cp == nil { // Begin writes the first line atomically, so this is not ours
		return nil, fmt.Errorf("checkpoint %s has no complete line: not a checkpoint file?", s.path)
	}
	// Cut a torn line off, or the next append would be glued to it.
	if err := f.Truncate(good); err != nil {
		return nil, err
	}
	return cp, nil
}

// Begin implements Store.
func (s *FileStore) Begin(_ context.Context, r Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(line{Run: &r})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(append(data, '\n')); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// SaveRecord implements Store.
func (s *FileStore) SaveRecord(_ context.Context, r Record) error { return s.append(line{Record: &r}) }

// SaveSession implements Store.
func (s *FileStore) SaveSession(_ context.Context, x result.Session) error {
	return s.append(line{Session: &x})
}

// Finish implements Store.
func (s *FileStore) Finish(_ context.Context, at time.Time) error {
	return s.append(line{Finished: &at})
}

func (s *FileStore) append(l line) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	if err != nil {
		f.Truncate(st.Size()) // e.g. disk full: leave no half line behind
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
