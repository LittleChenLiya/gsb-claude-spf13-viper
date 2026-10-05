// Copyright © 2026.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cast"
)

// SnapshotView is a read-only view over a parsed candidate configuration snapshot.
//
// Validators only receive a SnapshotView. It never touches the environment of
// the active Viper instance: no environment variables, bound flags, remote key
// value stores, or file reads are consulted. Values come exclusively from the
// configuration bytes that were parsed when the candidate was created.
//
// The view is immutable. Maps and slices returned from accessors are defensive
// copies, so validators cannot mutate the snapshot they received, any view
// derived from the same candidate, or nested values inside the snapshot.
//
// Key lookups are case-insensitive and support the active Viper key delimiter
// (".") for nested values, mirroring Viper's usual key semantics.
type SnapshotView interface {
	// Get returns the value at the given key path, or nil if it is not set.
	// Composite values (maps, slices) are returned as deep copies.
	Get(key string) any

	// IsSet reports whether the given key path exists in the snapshot.
	IsSet(key string) bool

	GetString(key string) string
	GetBool(key string) bool
	GetInt(key string) int
	GetInt32(key string) int32
	GetInt64(key string) int64
	GetUint(key string) uint
	GetUint8(key string) uint8
	GetUint16(key string) uint16
	GetUint32(key string) uint32
	GetUint64(key string) uint64
	GetFloat64(key string) float64
	GetTime(key string) time.Time
	GetDuration(key string) time.Duration
	GetIntSlice(key string) []int
	GetStringSlice(key string) []string
	GetStringMap(key string) map[string]any
	GetStringMapString(key string) map[string]string
	GetStringMapStringSlice(key string) map[string][]string

	// Sub returns a read-only view of a subtree of the snapshot, or nil if the
	// key does not identify a map. The returned view is backed by an
	// independent, read-only copy of the nested values.
	Sub(key string) SnapshotView
}

// snapshotView is the immutable, deep-copied map-backed SnapshotView.
type snapshotView struct {
	data  map[string]any
	delim string
}

var _ SnapshotView = (*snapshotView)(nil)

// newSnapshotView wraps data in a read-only view. data must already be
// case-insensitised and must not be shared with any mutable caller. Callers
// pass either a fresh parse result or a deep clone.
func newSnapshotView(data map[string]any, delim string) *snapshotView {
	if delim == "" {
		delim = "."
	}
	return &snapshotView{data: data, delim: delim}
}

// lookup walks the snapshot following the key path case-insensitively.
// found reports whether the full path resolved to a value (nil included).
func (s *snapshotView) lookup(key string) (any, bool) {
	path := strings.Split(strings.ToLower(key), s.delim)
	var current any = s.data
	for _, part := range path {
		m, err := cast.ToStringMapE(current)
		if err != nil {
			return nil, false
		}
		next, ok := m[part]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func (s *snapshotView) Get(key string) any {
	val, ok := s.lookup(key)
	if !ok {
		return nil
	}
	return cloneValue(val)
}

func (s *snapshotView) IsSet(key string) bool {
	_, ok := s.lookup(key)
	return ok
}

func (s *snapshotView) GetString(key string) string          { return cast.ToString(s.Get(key)) }
func (s *snapshotView) GetBool(key string) bool              { return cast.ToBool(s.Get(key)) }
func (s *snapshotView) GetInt(key string) int                { return cast.ToInt(s.Get(key)) }
func (s *snapshotView) GetInt32(key string) int32            { return cast.ToInt32(s.Get(key)) }
func (s *snapshotView) GetInt64(key string) int64            { return cast.ToInt64(s.Get(key)) }
func (s *snapshotView) GetUint(key string) uint              { return cast.ToUint(s.Get(key)) }
func (s *snapshotView) GetUint8(key string) uint8            { return cast.ToUint8(s.Get(key)) }
func (s *snapshotView) GetUint16(key string) uint16          { return cast.ToUint16(s.Get(key)) }
func (s *snapshotView) GetUint32(key string) uint32          { return cast.ToUint32(s.Get(key)) }
func (s *snapshotView) GetUint64(key string) uint64          { return cast.ToUint64(s.Get(key)) }
func (s *snapshotView) GetFloat64(key string) float64        { return cast.ToFloat64(s.Get(key)) }
func (s *snapshotView) GetTime(key string) time.Time         { return cast.ToTime(s.Get(key)) }
func (s *snapshotView) GetDuration(key string) time.Duration { return cast.ToDuration(s.Get(key)) }
func (s *snapshotView) GetIntSlice(key string) []int {
	return cloneIntSlice(cast.ToIntSlice(s.Get(key)))
}
func (s *snapshotView) GetStringSlice(key string) []string {
	return cloneStringSlice(cast.ToStringSlice(s.Get(key)))
}
func (s *snapshotView) GetStringMap(key string) map[string]any {
	return cloneAnyMap(cast.ToStringMap(s.Get(key)))
}
func (s *snapshotView) GetStringMapString(key string) map[string]string {
	return cloneStringMap(cast.ToStringMapString(s.Get(key)))
}
func (s *snapshotView) GetStringMapStringSlice(key string) map[string][]string {
	in := cast.ToStringMapStringSlice(s.Get(key))
	out := make(map[string][]string, len(in))
	for k, item := range in {
		out[k] = cloneStringSlice(item)
	}
	return out
}

func (s *snapshotView) Sub(key string) SnapshotView {
	val, ok := s.lookup(key)
	if !ok || val == nil {
		return nil
	}
	// Only actual map values form a subtree; scalars and slices yield nil,
	// mirroring Viper's own Sub semantics.
	if _, isMap := val.(map[string]any); !isMap {
		if _, isAnyMap := val.(map[any]any); !isAnyMap {
			return nil
		}
	}
	sub := cloneAnyMap(cast.ToStringMap(val))
	if sub == nil {
		return nil
	}
	return newSnapshotView(sub, s.delim)
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneIntSlice(in []int) []int {
	if in == nil {
		return nil
	}
	out := make([]int, len(in))
	copy(out, in)
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, item := range in {
		out[k] = item
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	cloned, ok := cloneValue(in).(map[string]any)
	if !ok {
		return nil
	}
	return cloned
}

// cloneValue returns a deep copy of a decoded configuration value. It covers
// the types produced by Viper's codecs: nested maps (string- or any-keyed),
// slices of arbitrary elements, and scalars which are returned untouched.
func cloneValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = cloneValue(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[fmt.Sprint(k)] = cloneValue(item)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return val
	}
}

// CandidateOption configures a [Candidate] at creation time.
type CandidateOption interface {
	applyCandidate(*candidateOptions)
}

type candidateOptionFunc func(*candidateOptions)

func (fn candidateOptionFunc) applyCandidate(o *candidateOptions) { fn(o) }

type candidateOptions struct {
	configType string
}

// WithCandidateConfigType explicitly sets the configuration format ("yaml",
// "json", "toml", ...) used to parse the candidate bytes, instead of deriving
// it from the active Viper instance's configured type.
func WithCandidateConfigType(format string) CandidateOption {
	return candidateOptionFunc(func(o *candidateOptions) {
		o.configType = strings.TrimSpace(format)
	})
}

// Candidate is a candidate configuration snapshot parsed exactly once from a
// byte stream, independently of the active Viper environment.
//
// A Candidate is safe for concurrent use after creation: views are immutable
// and Publish is serialized.
type Candidate struct {
	target *Viper

	// parsed is the single parse result. It is populated eagerly by
	// NewCandidate, so the same snapshot is never parsed twice.
	parsed map[string]any
	delim  string

	publishMu sync.Mutex
}

// NewCandidate parses the candidate configuration exactly once and returns a
// snapshot bound to target, the Viper instance it may later be published to.
//
// Parsing happens on an isolated scratch Viper instance and never mutates the
// active configuration (env, flags, overrides, defaults and remote stores are
// all untouched). A parse error is returned directly instead of flowing through
// validators, and leaves the target's active values unchanged.
//
// The format is derived from the target's configured config type unless
// [WithCandidateConfigType] is supplied.
func NewCandidate(target *Viper, in io.Reader, opts ...CandidateOption) (*Candidate, error) {
	if target == nil {
		target = v
	}

	o := candidateOptions{}
	for _, opt := range opts {
		opt.applyCandidate(&o)
	}

	// Parse on a throwaway Viper instance that shares the target's codec
	// registry and key delimiter, but none of its live state.
	scratch := New()
	scratch.decoderRegistry = target.decoderRegistry
	scratch.keyDelim = target.keyDelim
	if o.configType != "" {
		scratch.SetConfigType(o.configType)
	} else {
		scratch.SetConfigType(target.getConfigType())
	}

	parsed := make(map[string]any)
	if err := scratch.unmarshalReader(in, parsed); err != nil {
		return nil, err
	}

	return &Candidate{
		target: target,
		parsed: parsed,
		delim:  target.keyDelim,
	}, nil
}

// View returns the immutable, read-only [SnapshotView] of the candidate.
//
// Every call returns a view backed by an independent deep copy of the parsed
// snapshot, so validators cannot affect each other even when they mutate the
// maps returned by the view.
func (c *Candidate) View() SnapshotView {
	return newSnapshotView(cloneAnyMap(c.parsed), c.delim)
}

// Publish installs the parsed snapshot into the target Viper instance.
//
// This is the single hand-off point for a validated candidate. It atomically
// replaces the target's config-file layer with a deep copy of the parsed
// snapshot; overrides, flags, environment variables, defaults and remote
// stores are left intact. Calls are serialized.
//
// Publish is deliberately manual: the validation pipeline never publishes by
// itself, and config file watchers never publish candidates automatically.
func (c *Candidate) Publish() error {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()

	return c.install(c.target)
}

// install replaces the target config layer with an independent copy of the
// snapshot so later publishes or caller mutations cannot alias stored data.
func (c *Candidate) install(target *Viper) error {
	if target == nil {
		return fmt.Errorf("cannot publish candidate: target viper is nil")
	}
	target.config = cloneAnyMap(c.parsed)
	return nil
}
