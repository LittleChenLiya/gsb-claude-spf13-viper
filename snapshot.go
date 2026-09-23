package viper

import (
	"context"
	"errors"
	"reflect"
	"sync"
)

// ValidateFunc inspects a candidate snapshot before it is published. The
// settings map passed to it is a private deep copy, so a validator may read
// (but cannot corrupt) the candidate. Returning a non-nil error rejects the
// candidate and leaves the currently published snapshot untouched.
type ValidateFunc func(settings map[string]any) error

var (
	// ErrPublisherClosed is returned by Build and Publish once the Publisher
	// has been closed.
	ErrPublisherClosed = errors.New("viper: snapshot publisher is closed")

	// ErrStaleGeneration is returned by Publish when a newer generation has
	// already been published, so an older candidate that finishes late may
	// not overwrite it.
	ErrStaleGeneration = errors.New("viper: candidate belongs to a stale generation")

	// ErrCandidateConsumed is returned when a candidate is published more
	// than once.
	ErrCandidateConsumed = errors.New("viper: candidate has already been consumed")
)

// Publisher produces immutable configuration snapshots from a source Viper
// instance and publishes them atomically to readers.
//
// The source Viper must be fully configured before NewPublisher is called
// and must not be modified concurrently afterwards; every Build re-reads the
// effective settings from it. The usual source precedence (override, flag,
// env, config, key/value store, default) and case-insensitive key handling
// are preserved, because Build resolves values through the source Viper
// itself. Environment variables are sampled exactly once, at the beginning
// of Build.
//
// A candidate becomes visible to readers only after it passes validation and
// Publish succeeds. Every successful Publish increments the version; failed
// validations, stale generations, cancelled contexts and closed publishers
// never change the published snapshot or its version.
//
// Publisher does not hook into WatchConfig: reacting to file notifications
// stays explicit. An application wires them together itself:
//
//	v.OnConfigChange(func(e fsnotify.Event) {
//		candidate, err := publisher.Build(context.Background())
//		if err != nil {
//			return
//		}
//		if _, err := candidate.Publish(context.Background()); err != nil {
//			// validation failed or a newer generation won; keep old snapshot
//		}
//	})
//	v.WatchConfig()
type Publisher struct {
	src      *Viper
	validate ValidateFunc

	mu         sync.Mutex
	current    *Snapshot
	version    uint64
	generation uint64
	closed     bool
}

// NewPublisher creates a Publisher over src and eagerly builds and publishes
// the initial snapshot (generation 0, version 1). If validate is non-nil the
// initial settings must pass it, otherwise NewPublisher fails.
func NewPublisher(src *Viper, validate ValidateFunc) (*Publisher, error) {
	if src == nil {
		return nil, errors.New("viper: nil source Viper")
	}

	settings := deepCopyMap(src.AllSettings())
	if validate != nil {
		if err := validate(deepCopyMap(settings)); err != nil {
			return nil, err
		}
	}

	return &Publisher{
		src:      src,
		validate: validate,
		current:  &Snapshot{version: 1, generation: 0, settings: settings},
		version:  1,
	}, nil
}

// Build snapshots the effective settings of the source Viper into a new
// candidate. The candidate is a deep copy: later mutations of the source
// Viper, of environment variables, or of nested maps and slices obtained
// from either of them cannot affect it.
//
// Each Build is assigned a monotonically increasing generation. If a newer
// generation is published before this candidate, its Publish fails with
// ErrStaleGeneration.
func (p *Publisher) Build(ctx context.Context) (*Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPublisherClosed
	}
	p.generation++
	generation := p.generation
	p.mu.Unlock()

	// AllSettings resolves every key through the source Viper, sampling
	// environment variables once, here, at Build time.
	settings := deepCopyMap(p.src.AllSettings())

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &Candidate{pub: p, generation: generation, settings: settings}, nil
}

// Load returns the currently published snapshot. The returned Snapshot is
// immutable and safe for concurrent use; it stays readable even after the
// Publisher is closed or newer versions are published.
func (p *Publisher) Load() *Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

// Version returns the version of the currently published snapshot.
func (p *Publisher) Version() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// Close shuts the Publisher down: subsequent Build and Publish calls fail
// with ErrPublisherClosed. Snapshots obtained earlier remain readable.
func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// Candidate is an unpublished, immutable snapshot produced by Build.
type Candidate struct {
	pub        *Publisher
	generation uint64
	settings   map[string]any

	mu       sync.Mutex
	consumed bool
}

// Generation returns the generation assigned to this candidate at Build time.
func (c *Candidate) Generation() uint64 {
	return c.generation
}

// Settings returns a deep copy of the candidate's effective settings.
func (c *Candidate) Settings() map[string]any {
	return deepCopyMap(c.settings)
}

// Publish validates the candidate and, on success, atomically swaps it in as
// the current snapshot. The validation callback runs without holding the
// publish lock, so it may perform arbitrary work without blocking readers.
//
// The whole candidate is published or nothing is: a failed validation, a
// cancelled context, a closed publisher or a stale generation leaves the
// previously published snapshot and its version untouched. A candidate can
// be published at most once.
func (c *Candidate) Publish(ctx context.Context) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.consumed {
		c.mu.Unlock()
		return nil, ErrCandidateConsumed
	}
	c.consumed = true
	c.mu.Unlock()

	p := c.pub

	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, ErrPublisherClosed
	}

	// Validation runs outside the publish lock and on a private copy, so
	// the validator can neither block readers nor mutate the candidate.
	if p.validate != nil {
		if err := p.validate(deepCopyMap(c.settings)); err != nil {
			return nil, err
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPublisherClosed
	}
	if c.generation <= p.current.generation {
		return nil, ErrStaleGeneration
	}

	p.version++
	snapshot := &Snapshot{version: p.version, generation: c.generation, settings: c.settings}
	p.current = snapshot
	return snapshot, nil
}

// Snapshot is an immutable, published view of the configuration. Get and
// Unmarshal read exclusively from this snapshot; nested maps and slices
// returned by it are deep copies, so callers cannot mutate published state.
type Snapshot struct {
	version    uint64
	generation uint64
	settings   map[string]any

	once   sync.Once
	reader *Viper
}

// Version returns the published version of this snapshot.
func (s *Snapshot) Version() uint64 {
	return s.version
}

// reader lazily wraps the immutable settings in a private Viper so that key
// lookup keeps Viper's exact case-insensitive semantics. The wrapper has no
// flags, env bindings, defaults or overrides, so it reads only the snapshot.
func (s *Snapshot) getReader() *Viper {
	s.once.Do(func() {
		v := New()
		v.config = s.settings
		s.reader = v
	})
	return s.reader
}

// Get returns the value associated with key, deep-copied when it is a map or
// slice. The lookup is case-insensitive, like Viper.Get.
func (s *Snapshot) Get(key string) any {
	return deepCopyValue(s.getReader().Get(key))
}

// GetString returns the value associated with key as a string.
func (s *Snapshot) GetString(key string) string {
	return s.getReader().GetString(key)
}

// GetInt returns the value associated with key as an int.
func (s *Snapshot) GetInt(key string) int {
	return s.getReader().GetInt(key)
}

// GetBool returns the value associated with key as a bool.
func (s *Snapshot) GetBool(key string) bool {
	return s.getReader().GetBool(key)
}

// AllSettings returns a deep copy of all settings in this snapshot.
func (s *Snapshot) AllSettings() map[string]any {
	return deepCopyMap(s.settings)
}

// Unmarshal decodes this snapshot into rawVal, exactly like Viper.Unmarshal
// but reading only the snapshot.
func (s *Snapshot) Unmarshal(rawVal any, opts ...DecoderConfigOption) error {
	return s.getReader().Unmarshal(rawVal, opts...)
}

// deepCopyMap returns a deep copy of m.
func deepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	cp, _ := deepCopyValue(m).(map[string]any)
	return cp
}

// deepCopyValue copies maps and slices recursively; scalars are returned as
// is. Unknown map and slice types are handled via reflection so that nested
// containers can never alias published state.
func deepCopyValue(val any) any {
	switch t := val.(type) {
	case map[string]any:
		cp := make(map[string]any, len(t))
		for k, v := range t {
			cp[k] = deepCopyValue(v)
		}
		return cp
	case []any:
		cp := make([]any, len(t))
		for i, v := range t {
			cp[i] = deepCopyValue(v)
		}
		return cp
	}

	rv := reflect.ValueOf(val)
	if !rv.IsValid() {
		return nil
	}

	switch rv.Kind() {
	case reflect.Map:
		cp := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for iter := rv.MapRange(); iter.Next(); {
			elem := deepCopyValue(iter.Value().Interface())
			if elem == nil {
				cp.SetMapIndex(iter.Key(), reflect.Zero(rv.Type().Elem()))
			} else {
				cp.SetMapIndex(iter.Key(), reflect.ValueOf(elem))
			}
		}
		return cp.Interface()
	case reflect.Slice:
		cp := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			elem := deepCopyValue(rv.Index(i).Interface())
			if elem == nil {
				cp.Index(i).Set(reflect.Zero(rv.Type().Elem()))
			} else {
				cp.Index(i).Set(reflect.ValueOf(elem))
			}
		}
		return cp.Interface()
	}

	return val
}
