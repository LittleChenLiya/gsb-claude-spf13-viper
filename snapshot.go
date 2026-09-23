package viper

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/cast"
)

// ErrSnapshotPublisherClosed is returned by Build and Publish once the
// publisher has been closed.
var ErrSnapshotPublisherClosed = errors.New("viper: snapshot publisher is closed")

// ErrStaleSnapshotGeneration is returned by Publish when a newer generation
// has already been published and the candidate would roll the published
// snapshot back to an older generation.
var ErrStaleSnapshotGeneration = errors.New("viper: snapshot candidate belongs to a stale generation")

// SnapshotValidateFunc validates a candidate snapshot before it is published.
// Returning a non-nil error rejects the candidate; the currently published
// snapshot and its version are left untouched.
//
// The callback is never invoked while the publisher's publish lock is held,
// so it may perform arbitrary (even blocking) work.
type SnapshotValidateFunc func(s *Snapshot) error

// Snapshot is an immutable, deep-copied view of the whole configuration at a
// specific version. Snapshots obtained from Load remain fully readable after
// newer versions are published and after the publisher is closed.
type Snapshot struct {
	version  uint64
	settings map[string]any

	keyDelim string
	source   *Viper // only used for decoder configuration, never for reads
}

// Version returns the published version of the snapshot. Versions start at 1
// and increase by one on every successful Publish.
func (s *Snapshot) Version() uint64 { return s.version }

// Get returns the value associated with the key from this snapshot only.
// Get is case-insensitive for a key. Nested maps and slices are returned as
// deep copies, so callers cannot mutate the published snapshot through them.
func (s *Snapshot) Get(key string) any {
	lcaseKey := strings.ToLower(key)
	path := strings.Split(lcaseKey, s.keyDelim)

	var val any = s.settings
	for _, p := range path {
		m, ok := val.(map[string]any)
		if !ok {
			return nil
		}
		val, ok = m[p]
		if !ok {
			return nil
		}
	}

	return deepCopySnapshotValue(val)
}

// GetString returns the value associated with the key as a string.
func (s *Snapshot) GetString(key string) string { return cast.ToString(s.Get(key)) }

// GetInt returns the value associated with the key as an int.
func (s *Snapshot) GetInt(key string) int { return cast.ToInt(s.Get(key)) }

// GetBool returns the value associated with the key as a boolean.
func (s *Snapshot) GetBool(key string) bool { return cast.ToBool(s.Get(key)) }

// AllSettings returns a deep copy of all settings of this snapshot.
func (s *Snapshot) AllSettings() map[string]any {
	return deepCopySnapshotValue(s.settings).(map[string]any)
}

// Unmarshal decodes this snapshot (and only this snapshot) into a struct.
func (s *Snapshot) Unmarshal(rawVal any, opts ...DecoderConfigOption) error {
	return decode(s.settings, s.source.defaultDecoderConfig(rawVal, opts...))
}

// SnapshotCandidate is an unpublished, deep-copied snapshot produced by
// Build. It is not safe for concurrent use; publish it from a single
// goroutine.
type SnapshotCandidate struct {
	publisher  *SnapshotPublisher
	generation uint64
	settings   map[string]any
	keyDelim   string
}

// Generation returns the generation allocated to this candidate at Build
// time. Generations increase monotonically per publisher.
func (c *SnapshotCandidate) Generation() uint64 { return c.generation }

// Publish validates the candidate and, on success, atomically replaces the
// published snapshot. The validation callback runs before the publish lock
// is taken. If validation fails, the context is canceled, the publisher is
// closed, or a newer generation has been published in the meantime, the
// currently published snapshot is kept whole and its version is unchanged.
func (c *SnapshotCandidate) Publish(ctx context.Context) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p := c.publisher

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrSnapshotPublisherClosed
	}
	var nextVersion uint64 = 1
	if current := p.current.Load(); current != nil {
		nextVersion = current.version + 1
	}
	p.mu.Unlock()

	// The version is provisional: another candidate may publish while
	// validation is running. It is finalized under the publish lock.
	snap := &Snapshot{
		version:  nextVersion,
		settings: c.settings,
		keyDelim: c.keyDelim,
		source:   p.source,
	}

	// Validate without holding the publish lock.
	if p.validate != nil {
		if err := p.validate(snap); err != nil {
			return nil, err
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrSnapshotPublisherClosed
	}
	if c.generation <= p.publishedGeneration {
		return nil, ErrStaleSnapshotGeneration
	}

	snap.version = 1
	if current := p.current.Load(); current != nil {
		snap.version = current.version + 1
	}
	p.publishedGeneration = c.generation
	p.current.Store(snap)

	return snap, nil
}

// SnapshotPublisher builds validated, immutable snapshots of a Viper
// instance's effective configuration and publishes them atomically for
// readers. It does not change Viper's existing WatchConfig behavior; wiring
// file-change notifications to Build/Publish is left to the application.
//
// The source Viper is expected to be fully configured and free of external
// concurrent modification while a Build is in progress.
type SnapshotPublisher struct {
	source   *Viper
	validate SnapshotValidateFunc

	mu                  sync.Mutex // guards closed, generation, publishedGeneration
	closed              bool
	generation          uint64
	publishedGeneration uint64

	current atomic.Pointer[Snapshot]
}

// NewSnapshotPublisher creates a publisher over source and immediately
// builds, validates, and publishes the initial snapshot (version 1). If the
// validation callback rejects the initial configuration, an error is
// returned and no publisher is created.
func NewSnapshotPublisher(source *Viper, validate SnapshotValidateFunc) (*SnapshotPublisher, error) {
	if source == nil {
		return nil, errors.New("viper: snapshot publisher requires a non-nil source")
	}

	p := &SnapshotPublisher{source: source, validate: validate}

	candidate, err := p.Build(context.Background())
	if err != nil {
		return nil, err
	}
	if _, err := candidate.Publish(context.Background()); err != nil {
		return nil, err
	}

	return p, nil
}

// Build samples the source Viper's effective configuration exactly once
// (environment variables included) and returns a deep-copied candidate
// snapshot. Later changes to the source, to environment variables, or to
// nested containers previously handed out by the source do not affect the
// candidate.
func (p *SnapshotPublisher) Build(ctx context.Context) (*SnapshotCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrSnapshotPublisherClosed
	}
	p.generation++
	generation := p.generation
	p.mu.Unlock()

	// AllSettings resolves the full precedence chain (override, flag, env,
	// config, kvstore, default) in a single pass; the result is deep-copied
	// so the candidate is detached from the source from this point on.
	settings := deepCopySnapshotValue(p.source.AllSettings()).(map[string]any)

	return &SnapshotCandidate{
		publisher:  p,
		generation: generation,
		settings:   settings,
		keyDelim:   p.source.keyDelim,
	}, nil
}

// Load returns the currently published snapshot. It never blocks and never
// returns nil. The returned snapshot stays valid and readable forever, even
// after newer versions are published or the publisher is closed.
func (p *SnapshotPublisher) Load() *Snapshot { return p.current.Load() }

// Close marks the publisher as closed. Subsequent Build and Publish calls
// fail with ErrSnapshotPublisherClosed. Snapshots previously obtained via
// Load remain readable.
func (p *SnapshotPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// deepCopySnapshotValue recursively copies maps and slices so that neither
// the source's callers nor snapshot readers can mutate shared state.
func deepCopySnapshotValue(val any) any {
	if val == nil {
		return nil
	}

	rv := reflect.ValueOf(val)
	switch rv.Kind() {
	case reflect.Map:
		cp := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			cp.SetMapIndex(iter.Key(), deepCopySnapshotReflectValue(iter.Value()))
		}
		return cp.Interface()
	case reflect.Slice:
		cp := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			cp.Index(i).Set(deepCopySnapshotReflectValue(rv.Index(i)))
		}
		return cp.Interface()
	default:
		return val
	}
}

func deepCopySnapshotReflectValue(rv reflect.Value) reflect.Value {
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		return reflect.ValueOf(deepCopySnapshotValue(rv.Interface()))
	case reflect.Interface:
		if rv.IsNil() {
			return rv
		}
		return reflect.ValueOf(deepCopySnapshotValue(rv.Interface()))
	default:
		return rv
	}
}
