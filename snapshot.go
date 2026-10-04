// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/spf13/cast"
)

// Layer identifies a configuration source layer in Viper's precedence order.
//
// The precedence (highest first) is:
//
//	override > env > file > default
//
// This mirrors Viper's merge rules: explicitly set (override) values win,
// then environment variables, then the config file, then defaults.
type Layer uint8

const (
	// LayerDefault is the lowest-precedence layer (SetDefault).
	LayerDefault Layer = iota

	// LayerFile is the config file layer (ReadInConfig / MergeConfig).
	LayerFile

	// LayerEnv is the environment variable layer (BindEnv / AutomaticEnv).
	LayerEnv

	// LayerOverride is the highest-precedence layer (Set / explicit settings).
	LayerOverride
)

// String returns the lowercase name of the layer.
func (l Layer) String() string {
	switch l {
	case LayerDefault:
		return "default"
	case LayerFile:
		return "file"
	case LayerEnv:
		return "env"
	case LayerOverride:
		return "override"
	default:
		return "unknown"
	}
}

// Value is a resolved configuration value tagged with the layer that provided it.
//
// Present reports whether the key was found in any layer. A key may be present
// with a nil value (null) or an empty string; those are distinct from a missing key.
type Value struct {
	// Layer is the highest-precedence layer that provided the value.
	Layer Layer

	// Value is the resolved value. It is nil for a null value or a shadowed key.
	Value any

	// Present reports whether the key exists in any layer.
	Present bool
}

// String renders the value for diagnostics. Missing keys render as <missing>,
// nil values render as <nil>, and everything else renders with %v.
func (v Value) String() string {
	if !v.Present {
		return "<missing>"
	}
	if v.Value == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v", v.Value)
}

// layerString renders the source layer, or <missing> when the key is absent.
func (v Value) layerString() string {
	if !v.Present {
		return "<missing>"
	}
	return v.Layer.String()
}

// Equal reports whether two values are equivalent, including their source layer
// and presence.
func (v Value) Equal(other Value) bool {
	if v.Present != other.Present {
		return false
	}
	if !v.Present {
		return true
	}
	if v.Layer != other.Layer {
		return false
	}
	return reflect.DeepEqual(v.Value, other.Value)
}

// Change describes the difference between two snapshots for a single key.
type Change struct {
	// Key is the normalized (lower-cased, alias-resolved) configuration key.
	Key string

	// Old is the effective value in the base snapshot.
	Old Value

	// New is the effective value in the target snapshot.
	New Value

	// Sensitive reports whether the key is marked sensitive. Sensitive keys
	// omit their values from the diagnostic output; only the change and the
	// source layers are reported.
	Sensitive bool
}

// String renders the change in a stable, human-readable diagnostic format.
//
// Normal keys render as:
//
//	key: old -> new (source: oldlayer -> newlayer)
//
// Sensitive keys render as:
//
//	key: changed (source: oldlayer -> newlayer)
//
// Missing keys render as <missing>; null values render as <nil>.
func (c Change) String() string {
	if c.Sensitive {
		return fmt.Sprintf("%s: changed (source: %s -> %s)", c.Key, c.Old.layerString(), c.New.layerString())
	}
	return fmt.Sprintf("%s: %s -> %s (source: %s -> %s)", c.Key, c.Old, c.New, c.Old.layerString(), c.New.layerString())
}

// Snapshot is a read-only, point-in-time recording of configuration layers.
//
// Callers submit the default, file, env, and override layers as read-only
// snapshots. The snapshot copies and normalizes the values so that later
// mutation of the caller's maps does not affect the snapshot. The diff
// operation is pure computation: it never re-reads the environment and never
// triggers config watchers.
type Snapshot struct {
	defaults map[string]any
	file     map[string]any
	env      map[string]any
	override map[string]any

	keyDelim  string
	aliases   map[string]string
	sensitive map[string]struct{}
}

// SnapshotOption configures a Snapshot.
type SnapshotOption func(*Snapshot)

// WithKeyDelim sets the delimiter used for splitting nested keys.
// By default it is ".".
func WithKeyDelim(delim string) SnapshotOption {
	return func(s *Snapshot) {
		if delim != "" {
			s.keyDelim = delim
		}
	}
}

// WithAliases sets the alias map used to resolve keys before lookup.
// Keys and aliases are normalized to lower case.
func WithAliases(aliases map[string]string) SnapshotOption {
	return func(s *Snapshot) {
		s.aliases = make(map[string]string, len(aliases))
		for k, v := range aliases {
			s.aliases[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
}

// WithSensitiveKeys marks keys as sensitive. Sensitive keys report only their
// change and source layers; their values are never exported.
func WithSensitiveKeys(keys ...string) SnapshotOption {
	return func(s *Snapshot) {
		for _, k := range keys {
			s.sensitive[strings.ToLower(k)] = struct{}{}
		}
	}
}

// NewSnapshot creates a new, empty snapshot.
func NewSnapshot(opts ...SnapshotOption) *Snapshot {
	s := &Snapshot{
		defaults:  make(map[string]any),
		file:      make(map[string]any),
		env:       make(map[string]any),
		override:  make(map[string]any),
		keyDelim:  ".",
		aliases:   make(map[string]string),
		sensitive: make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// layerMap returns the backing map for the given layer.
func (s *Snapshot) layerMap(l Layer) map[string]any {
	switch l {
	case LayerDefault:
		return s.defaults
	case LayerFile:
		return s.file
	case LayerEnv:
		return s.env
	case LayerOverride:
		return s.override
	default:
		return nil
	}
}

// RecordLayer stores a read-only copy of the values for the given layer.
//
// Keys are normalized to lower case and nested maps are copied, so later
// mutation of the caller's map does not affect the snapshot. The env layer is
// flattened to dotted keys (matching Viper's flat env representation); the
// other layers retain their nested structure.
func (s *Snapshot) RecordLayer(l Layer, values map[string]any) {
	dst := s.layerMap(l)
	if dst == nil {
		return
	}
	if l == LayerEnv {
		for k, v := range flattenToFlatKeys(values, s.keyDelim) {
			dst[k] = v
		}
		return
	}
	for k, v := range values {
		dst[strings.ToLower(k)] = copySnapshotValue(v)
	}
}

// normalizeKey lower-cases the key and resolves aliases, mirroring Viper's
// key normalization and realKey alias resolution.
func (s *Snapshot) normalizeKey(key string) string {
	key = strings.ToLower(key)
	for {
		real, ok := s.aliases[key]
		if !ok {
			return key
		}
		key = real
	}
}

// isSensitive reports whether the normalized key is marked sensitive.
func (s *Snapshot) isSensitive(key string) bool {
	_, ok := s.sensitive[key]
	return ok
}

// layerLookupResult is the result of looking up a key in a single layer.
type layerLookupResult uint8

const (
	// layerAbsent: the key is not present in the layer.
	layerAbsent layerLookupResult = iota

	// layerPresent: the key is present in the layer (value may be nil).
	layerPresent

	// layerShadowed: a scalar parent shadows the key in the layer.
	layerShadowed
)

// lookupInLayer searches a single layer for a normalized key path.
//
// usePathPrefixes enables Viper's config-file search (which merges dotted
// flat keys with nested maps). It is used for the file layer only.
func (s *Snapshot) lookupInLayer(layerMap map[string]any, path []string, usePathPrefixes bool) (any, layerLookupResult) {
	// Search first, mirroring Viper's find() order.
	var val any
	var present bool
	if usePathPrefixes {
		val, present = searchIndexablePresence(layerMap, path, s.keyDelim)
	} else {
		val, present = searchMapPresence(layerMap, path)
	}
	if present {
		return val, layerPresent
	}

	// Not found: check whether a scalar parent shadows the path.
	if shadow := shadowedByDeep(layerMap, path, s.keyDelim); shadow != "" {
		return nil, layerShadowed
	}
	return nil, layerAbsent
}

// lookupEnv searches the env layer (a flat dotted-key map) for a key.
func (s *Snapshot) lookupEnv(layerMap map[string]any, lcaseKey string, path []string) (any, layerLookupResult) {
	if val, ok := layerMap[lcaseKey]; ok {
		return val, layerPresent
	}
	if shadow := shadowedByFlat(layerMap, path, s.keyDelim); shadow != "" {
		return nil, layerShadowed
	}
	return nil, layerAbsent
}

// Effective returns the effective value for key and the layer that provides it.
//
// The key is normalized (lower-cased, aliases resolved) before lookup, and
// the precedence follows Viper's rules: override > env > file > default.
// A key present with a nil value is reported as present (null); a key set to
// an empty string is reported as present with an empty value; a key absent
// from every layer is reported as not present.
func (s *Snapshot) Effective(key string) Value {
	lcaseKey := s.normalizeKey(key)
	path := strings.Split(lcaseKey, s.keyDelim)

	type layerEntry struct {
		layer Layer
		flat  bool
	}
	// Precedence: override, env, file, default.
	entries := []layerEntry{
		{layer: LayerOverride, flat: false},
		{layer: LayerEnv, flat: true},
		{layer: LayerFile, flat: false},
		{layer: LayerDefault, flat: false},
	}

	for _, e := range entries {
		var val any
		var res layerLookupResult
		layerMap := s.layerMap(e.layer)
		if e.flat {
			val, res = s.lookupEnv(layerMap, lcaseKey, path)
		} else {
			val, res = s.lookupInLayer(layerMap, path, e.layer == LayerFile)
		}
		switch res {
		case layerPresent:
			return Value{Layer: e.layer, Value: val, Present: true}
		case layerShadowed:
			return Value{Layer: e.layer, Value: nil, Present: true}
		}
	}
	return Value{Layer: LayerDefault, Value: nil, Present: false}
}

// allKeys collects every leaf key across all layers.
func (s *Snapshot) allKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	for _, layerMap := range [4]map[string]any{s.defaults, s.file, s.env, s.override} {
		for k := range collectLeafKeys(layerMap, s.keyDelim) {
			keys[k] = struct{}{}
		}
	}
	return keys
}

// Diff computes the changes from s to other.
//
// A change is reported for every key whose effective value or source layer
// differs between the two snapshots. Sensitive keys report only the change and
// the source layers; their values are not included. The returned changes are
// sorted by key for deterministic output.
func (s *Snapshot) Diff(other *Snapshot) []Change {
	keys := s.allKeys()
	for k := range other.allKeys() {
		keys[k] = struct{}{}
	}

	changes := make([]Change, 0, len(keys))
	for k := range keys {
		old := s.Effective(k)
		new := other.Effective(k)
		if old.Equal(new) {
			continue
		}
		sensitive := s.isSensitive(k) || other.isSensitive(k)
		if sensitive {
			// Sensitive keys report only the change and the source layers;
			// their values are never exported.
			old.Value = nil
			new.Value = nil
		}
		changes = append(changes, Change{
			Key:       k,
			Old:       old,
			New:       new,
			Sensitive: sensitive,
		})
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes
}

// copySnapshotValue deep-copies a value, lower-casing map keys recursively.
func copySnapshotValue(v any) any {
	switch x := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[strings.ToLower(fmt.Sprint(k))] = copySnapshotValue(val)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[strings.ToLower(k)] = copySnapshotValue(val)
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, val := range x {
			a[i] = copySnapshotValue(val)
		}
		return a
	default:
		return v
	}
}

// flattenToFlatKeys flattens nested maps into dotted keys. Flat dotted keys
// are preserved. Map keys are lower-cased.
func flattenToFlatKeys(m map[string]any, keyDelim string) map[string]any {
	result := make(map[string]any)
	var walk func(prefix string, val any)
	walk = func(prefix string, val any) {
		switch v := val.(type) {
		case map[any]any:
			for k, child := range v {
				key := strings.ToLower(fmt.Sprint(k))
				if prefix != "" {
					key = prefix + keyDelim + key
				}
				walk(key, child)
			}
		case map[string]any:
			for k, child := range v {
				key := strings.ToLower(k)
				if prefix != "" {
					key = prefix + keyDelim + key
				}
				walk(key, child)
			}
		default:
			result[prefix] = v
		}
	}
	walk("", m)
	return result
}

// collectLeafKeys returns the set of dotted leaf keys in a layer map.
// Nested maps are recursed; non-map values are treated as leaves.
func collectLeafKeys(m map[string]any, keyDelim string) map[string]struct{} {
	keys := make(map[string]struct{})
	var walk func(prefix string, val any)
	walk = func(prefix string, val any) {
		switch v := val.(type) {
		case map[any]any:
			for k, child := range v {
				key := strings.ToLower(fmt.Sprint(k))
				if prefix != "" {
					key = prefix + keyDelim + key
				}
				walk(key, child)
			}
		case map[string]any:
			for k, child := range v {
				key := strings.ToLower(k)
				if prefix != "" {
					key = prefix + keyDelim + key
				}
				walk(key, child)
			}
		default:
			keys[prefix] = struct{}{}
		}
	}
	walk("", m)
	return keys
}

// searchMapPresence walks a nested map and returns the value at path, along
// with whether the full path exists. A nil value is reported as present.
func searchMapPresence(source map[string]any, path []string) (any, bool) {
	if len(path) == 0 {
		return source, true
	}
	next, ok := source[path[0]]
	if !ok {
		return nil, false
	}
	if len(path) == 1 {
		return next, true
	}
	switch n := next.(type) {
	case map[any]any:
		return searchMapPresence(cast.ToStringMap(n), path[1:])
	case map[string]any:
		return searchMapPresence(n, path[1:])
	default:
		// Scalar parent: cannot descend.
		return nil, false
	}
}

// searchIndexablePresence searches a map for path, merging dotted flat keys
// with nested maps (Viper's config-file search). It returns the value and
// whether the path was found.
func searchIndexablePresence(source map[string]any, path []string, keyDelim string) (any, bool) {
	if len(path) == 0 {
		return source, true
	}
	for i := len(path); i > 0; i-- {
		prefixKey := strings.ToLower(strings.Join(path[0:i], keyDelim))
		next, ok := source[prefixKey]
		if !ok {
			continue
		}
		if i == len(path) {
			return next, true
		}
		switch n := next.(type) {
		case map[any]any:
			return searchIndexablePresence(cast.ToStringMap(n), path[i:], keyDelim)
		case map[string]any:
			return searchIndexablePresence(n, path[i:], keyDelim)
		default:
			// Scalar parent: cannot descend; try a shorter prefix.
		}
	}
	return nil, false
}

// shadowedByDeep returns the parent key that shadows path in a deep (nested)
// map, or "" if the path is not shadowed. A scalar parent shadows; a nil
// (null) parent does not, mirroring Viper's isPathShadowedInDeepMap.
func shadowedByDeep(layerMap map[string]any, path []string, keyDelim string) string {
	for i := 1; i < len(path); i++ {
		parent, present := searchMapPresence(layerMap, path[0:i])
		if !present {
			return ""
		}
		if parent == nil {
			return ""
		}
		switch parent.(type) {
		case map[any]any, map[string]any:
			continue
		default:
			return strings.Join(path[0:i], keyDelim)
		}
	}
	return ""
}

// shadowedByFlat returns the parent key that shadows path in a flat map, or
// "" if the path is not shadowed. Any present parent key shadows, mirroring
// Viper's isPathShadowedInFlatMap.
func shadowedByFlat(layerMap map[string]any, path []string, keyDelim string) string {
	for i := 1; i < len(path); i++ {
		parentKey := strings.Join(path[0:i], keyDelim)
		if _, ok := layerMap[parentKey]; ok {
			return parentKey
		}
	}
	return ""
}
