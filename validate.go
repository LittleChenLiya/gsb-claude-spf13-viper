// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"context"
	"errors"
	"io"
	"sync"
)

// Snapshot is a read-only view of a candidate configuration.
//
// A Snapshot is parsed exactly once (via [Viper.SnapshotFromReader]) and
// shared by every [Validator] registered with a [Pipeline]. The view never
// consults environment variables, flags, overrides, defaults, or any other
// state belonging to the active [Viper]: it exposes only the parsed
// candidate configuration, including nested values.
//
// Snapshot is safe for concurrent reads.
type Snapshot struct {
	// v is a private Viper that only ever has its config register
	// populated. Because overrides, flags, env, kvstore, and defaults are
	// all empty (and automatic env is off), every read through v resolves
	// to the candidate configuration and nothing else.
	v *Viper
}

// SnapshotFromReader parses a candidate configuration from r exactly once
// into a read-only [Snapshot].
//
// The receiver only supplies the configuration format and decoder
// registry; none of its active state (overrides, flags, env, defaults,
// ...) is read or copied. The returned snapshot is independent of the
// receiver and safe to validate concurrently.
func (v *Viper) SnapshotFromReader(in io.Reader) (*Snapshot, error) {
	if in == nil {
		return nil, errors.New("snapshot: nil reader")
	}

	cfg := make(map[string]any)
	if err := v.unmarshalReader(in, cfg); err != nil {
		return nil, err
	}

	return v.newSnapshot(cfg), nil
}

// SnapshotFromMap builds a read-only [Snapshot] from an already-parsed
// configuration map.
//
// The map is used as-is (it is not copied); callers must not mutate it
// after building the snapshot.
func (v *Viper) SnapshotFromMap(cfg map[string]any) *Snapshot {
	if cfg == nil {
		cfg = make(map[string]any)
	}
	return v.newSnapshot(cfg)
}

func (v *Viper) newSnapshot(cfg map[string]any) *Snapshot {
	snap := &Snapshot{v: New()}
	snap.v.keyDelim = v.keyDelim
	snap.v.config = cfg
	return snap
}

// Get returns the value associated with the key in the candidate
// configuration. Get is case-insensitive for a key and traverses nested
// maps using the viper key delimiter. It returns nil when the key is not
// present in the snapshot.
func (s *Snapshot) Get(key string) any { return s.v.Get(key) }

// GetString returns the value associated with the key as a string.
func (s *Snapshot) GetString(key string) string { return s.v.GetString(key) }

// GetBool returns the value associated with the key as a bool.
func (s *Snapshot) GetBool(key string) bool { return s.v.GetBool(key) }

// GetInt returns the value associated with the key as an int.
func (s *Snapshot) GetInt(key string) int { return s.v.GetInt(key) }

// GetFloat64 returns the value associated with the key as a float64.
func (s *Snapshot) GetFloat64(key string) float64 { return s.v.GetFloat64(key) }

// GetStringSlice returns the value associated with the key as a []string.
func (s *Snapshot) GetStringSlice(key string) []string { return s.v.GetStringSlice(key) }

// IsSet checks to see if the key holds a value in the candidate
// configuration. IsSet is case-insensitive for a key.
func (s *Snapshot) IsSet(key string) bool { return s.v.IsSet(key) }

// InConfig checks to see if the given key (or an alias) is in the
// candidate configuration.
func (s *Snapshot) InConfig(key string) bool { return s.v.InConfig(key) }

// AllSettings merges all settings from the candidate configuration and
// returns them as a map[string]any.
func (s *Snapshot) AllSettings() map[string]any { return s.v.AllSettings() }

// Unmarshal unmarshals the candidate configuration into a Struct. Make
// sure that the tags on the fields of the structure are properly set.
func (s *Snapshot) Unmarshal(rawVal any, opts ...DecoderConfigOption) error {
	return s.v.Unmarshal(rawVal, opts...)
}

// Validator validates a candidate [Snapshot].
//
// Validators are registered with a [Pipeline] and run concurrently. A
// validator must be safe to run concurrently with other validators and
// must not retain the snapshot after Validate returns.
type Validator interface {
	Validate(ctx context.Context, snap *Snapshot) error
}

// ValidatorFunc is an adapter that allows ordinary functions to be used
// as [Validator]s.
type ValidatorFunc func(ctx context.Context, snap *Snapshot) error

// Validate implements [Validator].
func (f ValidatorFunc) Validate(ctx context.Context, snap *Snapshot) error {
	return f(ctx, snap)
}

// ValidationResult is the outcome of a single registered [Validator].
type ValidationResult struct {
	// Name is the name the validator was registered with.
	Name string

	// Err is the error returned by the validator, or nil.
	Err error
}

// PublishFunc publishes a validated [Snapshot] into the target [Viper].
//
// A PublishFunc is only returned by [Pipeline.Validate] when every
// validator succeeded and the context was still live at aggregation
// time. Calling it merges the validated snapshot into the target viper's
// config register; it never touches overrides, flags, env, or defaults.
//
// If the context is canceled before or during the call, PublishFunc
// returns the context error and does not modify the target. The same
// PublishFunc may be called multiple times; each call re-checks the
// context.
type PublishFunc func(target *Viper) error

// Pipeline is an ordered collection of [Validator]s.
//
// Validators are registered in order and executed concurrently. Their
// [ValidationResult]s are always reported in registration order,
// regardless of completion order. A publish function is handed to the
// caller only when all validators pass.
//
// Pipeline is safe for concurrent use.
type Pipeline struct {
	mu         sync.RWMutex
	validators []pipelineValidator
}

type pipelineValidator struct {
	name string
	v    Validator
}

// NewPipeline returns an empty pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{}
}

// Add registers v under name. Validators are reported in registration
// order. Add returns the pipeline for chaining.
func (p *Pipeline) Add(name string, v Validator) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.validators = append(p.validators, pipelineValidator{name: name, v: v})
	return p
}

// Validate runs every registered validator concurrently against snap and
// aggregates the results in registration order.
//
// It returns a non-nil [PublishFunc] only when every validator reported
// success and ctx was still live when aggregation finished. If ctx is
// canceled, no publish function is returned: validators that finish late
// are discarded and cannot be published. Validation errors never modify
// any [Viper].
func (p *Pipeline) Validate(ctx context.Context, snap *Snapshot) (PublishFunc, []ValidationResult) {
	p.mu.RLock()
	validators := make([]pipelineValidator, len(p.validators))
	copy(validators, p.validators)
	p.mu.RUnlock()

	results := make([]ValidationResult, len(validators))

	if len(validators) == 0 {
		// No validators: nothing to validate, but still honor cancellation.
		if err := ctx.Err(); err != nil {
			return nil, results
		}
		return p.publishFunc(ctx, snap), results
	}

	var wg sync.WaitGroup
	for i, pv := range validators {
		wg.Add(1)
		go func(i int, pv pipelineValidator) {
			defer wg.Done()
			results[i] = ValidationResult{Name: pv.name, Err: pv.v.Validate(ctx, snap)}
		}(i, pv)
	}
	wg.Wait()

	for _, r := range results {
		if r.Err != nil {
			return nil, results
		}
	}

	// Cancellation gate: even if every validator succeeded, a canceled
	// context means the snapshot must not be published.
	if err := ctx.Err(); err != nil {
		return nil, results
	}

	return p.publishFunc(ctx, snap), results
}

func (p *Pipeline) publishFunc(ctx context.Context, snap *Snapshot) PublishFunc {
	return func(target *Viper) error {
		// Re-check cancellation at publish time so a context canceled
		// after aggregation but before publish still prevents publication.
		if err := ctx.Err(); err != nil {
			return err
		}
		if target == nil {
			return errors.New("snapshot publish: nil target viper")
		}
		return snap.publishTo(target)
	}
}

// publishTo merges the validated snapshot into the target viper's config
// register.
func (s *Snapshot) publishTo(target *Viper) error {
	return target.MergeConfigMap(s.v.config)
}
