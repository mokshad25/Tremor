package wal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// Checkpoint records, per shard, the highest sequence number S such that
// every event routed to that shard with seq <= S has been processed.
//
// It is only valid for the routing it was produced under, so the router's
// identity (algorithm + shard count) is stored alongside.
type Checkpoint struct {
	Version int      `json:"version"`
	Router  string   `json:"router"`
	Shards  []uint64 `json:"shards"`
}

const checkpointVersion = 1

// LoadCheckpoint reads path. found is false if the file does not exist.
func LoadCheckpoint(path string) (cp Checkpoint, found bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		return Checkpoint{}, false, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	if cp.Version != checkpointVersion {
		return Checkpoint{}, false, fmt.Errorf("checkpoint %s: unsupported version %d", path, cp.Version)
	}
	return cp, true, nil
}

// SaveCheckpoint writes cp atomically and durably: write a temp file, fsync
// it, rename it over path, fsync the directory. A crash at any point leaves
// either the old or the new checkpoint, never a torn one.
func SaveCheckpoint(path string, cp Checkpoint) error {
	cp.Version = checkpointVersion
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// RestoreShards maps a stored checkpoint onto the current shard layout.
//
// If the router or shard count changed, events may now route to a different
// shard than the one that checkpointed them, so per-shard values are no
// longer meaningful. Every shard then restarts from the minimum: some events
// are processed twice (at-least-once allows that), none are skipped.
func RestoreShards(cp Checkpoint, found bool, shards int, router string) (restored []uint64, reset bool) {
	restored = make([]uint64, shards)
	if !found || len(cp.Shards) == 0 {
		return restored, false
	}
	if cp.Router == router && len(cp.Shards) == shards {
		copy(restored, cp.Shards)
		return restored, false
	}
	low := slices.Min(cp.Shards)
	for i := range restored {
		restored[i] = low
	}
	return restored, true
}
