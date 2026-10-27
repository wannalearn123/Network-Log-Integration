package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// fileOffset is the persisted read position for one log file.
type fileOffset struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Tailer follows every *.log file in a directory and emits complete lines.
//
// Behaviour matches the original Python tailer:
//   - files present at startup are read from EOF (live-only ingestion)
//   - a file appearing later is read from the beginning
//   - rotation (inode change) and truncation (size shrank) reset the read
//     position instead of emitting garbage
//   - offsets are persisted atomically so a restart resumes mid-file
type Tailer struct {
	Dir          string
	StateFile    string
	PollInterval time.Duration
	SaveInterval time.Duration
	// InitialEOF starts pre-existing files at EOF. Nil means true.
	InitialEOF *bool
	// OnError, if set, receives non-fatal read errors.
	OnError func(error)
}

type tailStream struct {
	file       *os.File
	offset     int64
	buf        []byte
	discarding bool
}

// Run tails until ctx is cancelled, sending each complete line to out.
func (t *Tailer) Run(ctx context.Context, out chan<- string) error {
	poll := t.PollInterval
	if poll <= 0 {
		poll = 200 * time.Millisecond
	}
	saveEvery := t.SaveInterval
	if saveEvery <= 0 {
		saveEvery = time.Second
	}
	startAtEOF := true
	if t.InitialEOF != nil {
		startAtEOF = *t.InitialEOF
	}
	stateFile := t.StateFile
	if stateFile == "" {
		stateFile = filepath.Join(filepath.Dir(t.Dir), ".pipeline", "offsets.json")
	}

	offsets := loadOffsets(stateFile)
	initial := map[string]bool{}
	if matches, err := filepath.Glob(filepath.Join(t.Dir, "*.log")); err == nil {
		for _, m := range matches {
			initial[m] = true
		}
	}

	streams := map[string]*tailStream{}
	lastSave := time.Now()

	defer func() {
		for _, s := range streams {
			s.file.Close()
		}
		saveOffsets(stateFile, offsets)
	}()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		matches, err := filepath.Glob(filepath.Join(t.Dir, "*.log"))
		if err != nil {
			continue
		}
		for _, path := range matches {
			if ctx.Err() != nil {
				return nil
			}
			if err := t.track(ctx, path, streams, offsets, initial, startAtEOF, out); err != nil && t.OnError != nil {
				t.OnError(err)
			}
		}

		// Persist positions even when idle so a clean shutdown resumes exactly.
		// committedOffset excludes the buffered partial line, so a restart
		// re-reads lines that were never emitted.
		for path, s := range streams {
			key, err := filepath.Abs(path)
			if err != nil {
				key = path
			}
			if info, err := s.file.Stat(); err == nil {
				offsets[key] = fileOffset{Inode: inodeOf(info), Offset: committedOffset(s)}
			}
		}
		if time.Since(lastSave) >= saveEvery {
			saveOffsets(stateFile, offsets)
			lastSave = time.Now()
		}
	}
}

// track reads new bytes from one file, handling rotation and truncation.
func (t *Tailer) track(ctx context.Context, path string, streams map[string]*tailStream,
	offsets map[string]fileOffset, initial map[string]bool, startAtEOF bool,
	out chan<- string) error {

	info, err := os.Stat(path)
	if err != nil {
		if s, ok := streams[path]; ok {
			s.file.Close()
			delete(streams, path)
		}
		return err
	}
	key, err := filepath.Abs(path)
	if err != nil {
		key = path
	}
	inode := inodeOf(info)

	s := streams[path]
	if s != nil && inodeOfStream(s) != inode {
		s.file.Close()
		delete(streams, path)
		s = nil
	}

	if s == nil {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		s = &tailStream{file: f}
		streams[path] = s

		saved, hasSaved := offsets[key]
		switch {
		case hasSaved && saved.Inode == inode && saved.Offset >= 0 && saved.Offset <= info.Size():
			if _, err := f.Seek(saved.Offset, 0); err != nil {
				f.Close()
				delete(streams, path)
				return err
			}
			s.offset = saved.Offset
		case !hasSaved && startAtEOF && initial[path]:
			if _, err := f.Seek(0, 2); err != nil {
				f.Close()
				delete(streams, path)
				return err
			}
			s.offset = info.Size()
		}
		delete(initial, path)
	}

	// Truncation: the writer restarted the file in place, so its size shrank
	// below our read position. Re-seek to the start instead of emitting gaps.
	if info.Size() < s.offset {
		if _, err := s.file.Seek(0, 0); err != nil {
			return err
		}
		s.offset = 0
		s.buf = s.buf[:0]
		s.discarding = false
	}

	chunk := make([]byte, 64*1024)
	for {
		n, readErr := s.file.Read(chunk)
		if n > 0 {
			s.offset += int64(n)
			data := chunk[:n]

			// Drop the remainder of an oversized line up to the next newline.
			if s.discarding {
				idx := bytes.IndexByte(data, '\n')
				if idx < 0 {
					if readErr != nil || n == 0 {
						break
					}
					continue
				}
				s.discarding = false
				data = data[idx+1:]
			}

			s.buf = append(s.buf, data...)
			for {
				idx := bytes.IndexByte(s.buf, '\n')
				if idx < 0 {
					break
				}
				raw := s.buf[:idx]
				copy(s.buf, s.buf[idx+1:])
				s.buf = s.buf[:len(s.buf)-(idx+1)]
				// A single terminated line over the cap is dropped, not emitted.
				if len(raw) > MaxPartialLine {
					if t.OnError != nil {
						t.OnError(errOversizeLine)
					}
					continue
				}
				line := string(raw)
				select {
				case <-ctx.Done():
					return nil
				case out <- line:
				}
			}
			// A file that never emits a newline must not grow without bound.
			if len(s.buf) > MaxPartialLine {
				if t.OnError != nil {
					t.OnError(errOversizeLine)
				}
				s.discarding = true
				s.buf = s.buf[:0]
			}
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	offsets[key] = fileOffset{Inode: inode, Offset: committedOffset(s)}
	return nil
}

// MaxPartialLine bounds an unterminated line held in memory (1 MiB).
const MaxPartialLine = 1024 * 1024

var errOversizeLine = errors.New("tailer: dropped oversized line")

// committedOffset is the position up to which lines were safely emitted. Bytes
// still buffered as an incomplete line are not counted, so a restart re-reads
// them rather than losing data.
func committedOffset(s *tailStream) int64 {
	off := s.offset - int64(len(s.buf))
	if off < 0 {
		return 0
	}
	return off
}

func loadOffsets(path string) map[string]fileOffset {
	out := map[string]fileOffset{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]fileOffset{}
	}
	return out
}

// saveOffsets writes the offset map atomically (temp + fsync + rename).
func saveOffsets(path string, offsets map[string]fileOffset) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	raw, err := json.Marshal(offsets)
	if err != nil {
		return
	}
	f, err := os.CreateTemp(dir, "offsets-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

func inodeOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func inodeOfStream(s *tailStream) uint64 {
	info, err := s.file.Stat()
	if err != nil {
		return 0
	}
	return inodeOf(info)
}
