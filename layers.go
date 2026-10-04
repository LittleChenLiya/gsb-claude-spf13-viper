// Copyright © 2026 The Viper Authors.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Layer identifies one of the configuration sources that may provide a value.
// Layers are ordered by Viper's merge priority (lowest to highest):
//
//	LayerDefault < LayerFile < LayerEnv < LayerOverride
//
// The highest-priority layer that carries a value wins, following the same
// rules as [Viper.Get].
type Layer string

const (
	// LayerDefault holds values registered via SetDefault.
	LayerDefault Layer = "default"

	// LayerFile holds values decoded from configuration files.
	LayerFile Layer = "file"

	// LayerEnv holds values read from environment variables.
	LayerEnv Layer = "env"

	// LayerOverride holds values set explicitly via Set.
	LayerOverride Layer = "override"
)

// Layers lists the supported layers in merge-priority order (lowest first).
var Layers = []Layer{LayerDefault, LayerFile, LayerEnv, LayerOverride}

// presenceFor classifies a concrete value found in a layer.
func presenceFor(val any) Presence {
	switch {
	case val == nil:
		return PresenceNull
	case val == "":
		return PresenceEmpty
	default:
		return PresenceSet
	}
}

// Presence describes the state of a key in a specific layer or in the
// effective view of a snapshot.
//
// It deliberately distinguishes three "empty-ish" situations that Viper
// otherwise collapses: a key may be missing, explicitly set to null (nil),
// or set to an empty string. Empty strings are real values and are never
// reported as missing.
type Presence string

const (
	// PresenceMissing means the key does not exist in the layer.
	PresenceMissing Presence = "missing"

	// PresenceNull means the key exists but its value is null (nil).
	// Like [Viper.Get], a null value does not block lower-priority layers,
	// but unlike a missing key it is visible in the per-layer record.
	PresenceNull Presence = "null"

	// PresenceEmpty means the key exists and holds an empty string "".
	// An empty string is a real value: it shadows lower-priority layers.
	PresenceEmpty Presence = "empty"

	// PresenceSet means the key exists with a non-empty value.
	PresenceSet Presence = "set"

	// PresenceRedacted means the key exists, but the report is not allowed
	// to disclose its value (or its exact state) because the key is
	// sensitive.
	PresenceRedacted Presence = "redacted"
)

// LayerValue is the read-only record of a key in one layer.
type LayerValue struct {
	// Layer is the source layer this record comes from.
	Layer Layer

	// Presence describes whether the key is missing, null, empty or set.
	Presence Presence

	// Value is the raw value of the key in that layer. It is nil when the
	// key is missing or null. Values are never copied on read: callers must
	// treat them as immutable.
	Value any
}

// Exists reports whether the key is present in the layer, including null
// values and empty strings.
func (l LayerValue) Exists() bool {
	return l.Presence != PresenceMissing
}

// KeyTrace records where a single key gets its effective value from and what
// every individual layer contributed. It is the explicit layer record used by
// debugging reports.
type KeyTrace struct {
	// Key is the canonical (lower-cased, delimiter-joined) key.
	Key string

	// Effective is the winning layer, or empty when no layer provides a
	// value (all layers are missing or null).
	Effective Layer

	// EffectivePresence is the state of the winning value, or
	// PresenceMissing when no layer provides a value.
	EffectivePresence Presence

	// EffectiveValue is the winning value. It is nil for missing and null
	// effective values.
	EffectiveValue any

	// Layers records the contribution of every layer in priority order
	// (default, file, env, override).
	Layers map[Layer]LayerValue
}

// Snapshot is a read-only point-in-time view of the four configuration layers
// that participate in debugging and diffing:
//
//   - defaults registered by the caller,
//   - values decoded from configuration files,
//   - values bound to or matched from environment variables,
//   - explicit overrides set by the caller.
//
// Snapshots are immutable inputs for [Snapshot.Trace] and [Snapshot.Diff].
// Comparison works solely on the captured data: it never re-reads the
// environment, the file system or config watchers.
type Snapshot struct {
	keyDelim string

	aliases map[string]string

	defaults map[string]any
	file     map[string]any
	// env holds explicitly bound environment keys (Viper's v.env register,
	// materialized with their resolved values).
	env map[string]any
	// autoEnv holds environment keys discovered through AutomaticEnv with an
	// env prefix. When envPrefix is empty, AutomaticEnv can match arbitrary
	// process environment variables, which cannot be enumerated from a
	// snapshot alone; only the bound keys are then captured.
	autoEnv       map[string]any
	allowEmptyEnv bool
	automaticEnv  bool
	override      map[string]any
}

// SnapshotOption configures a [Snapshot] built with [NewSnapshot].
type SnapshotOption func(*snapshotOptions)

type snapshotOptions struct {
	keyDelim      string
	aliases       map[string]string
	allowEmptyEnv bool
	automaticEnv  bool
}

// SnapshotKeyDelimiter overrides the key delimiter used while traversing
// nested maps. It defaults to ".".
func SnapshotKeyDelimiter(d string) SnapshotOption {
	return func(o *snapshotOptions) {
		if d != "" {
			o.keyDelim = d
		}
	}
}

// SnapshotAliases provides alias-to-real-key mappings (the same register as
// [Viper.RegisterAlias]). Both sides are expected to use the configured key
// delimiter; keys are lower-cased by the snapshot.
func SnapshotAliases(aliases map[string]string) SnapshotOption {
	return func(o *snapshotOptions) {
		o.aliases = aliases
	}
}

// SnapshotAllowEmptyEnv makes empty-string environment values count as present,
// mirroring [Viper.AllowEmptyEnv]. By default empty environment values are
// considered absent and the next layer wins.
func SnapshotAllowEmptyEnv(allow bool) SnapshotOption {
	return func(o *snapshotOptions) {
		o.allowEmptyEnv = allow
	}
}

// SnapshotAutomaticEnv marks the environment map as the result of
// [Viper.AutomaticEnv], so the same shadowing rules applied by [Viper.Get] are
// used while resolving nested paths.
func SnapshotAutomaticEnv(automatic bool) SnapshotOption {
	return func(o *snapshotOptions) {
		o.automaticEnv = automatic
	}
}

// NewSnapshot builds a read-only snapshot from the four layer maps supplied by
// the caller.
//
// The input maps are copied (maps are deep-copied; leaf values are shared) so
// later mutation of the arguments cannot change a snapshot or a previously
// computed diff.
//
// Keys follow Viper's normalization: map keys are lower-cased and nested
// values are expressed as nested map[string]any values. The environment map
// uses flat, canonical (lower-cased) keys like the Viper BindEnv register;
// empty-string environment values are dropped unless SnapshotAllowEmptyEnv is
// enabled.
func NewSnapshot(defaults, file, env, override map[string]any, opts ...SnapshotOption) *Snapshot {
	o := snapshotOptions{keyDelim: "."}
	for _, opt := range opts {
		opt(&o)
	}

	s := &Snapshot{
		keyDelim:      o.keyDelim,
		aliases:       make(map[string]string, len(o.aliases)),
		defaults:      copyDeepMap(defaults),
		file:          copyDeepMap(file),
		env:           make(map[string]any),
		autoEnv:       make(map[string]any),
		allowEmptyEnv: o.allowEmptyEnv,
		automaticEnv:  o.automaticEnv,
		override:      copyDeepMap(override),
	}

	for alias, key := range o.aliases {
		s.aliases[strings.ToLower(alias)] = strings.ToLower(key)
	}

	for key, val := range env {
		if str, ok := val.(string); ok && str == "" && !o.allowEmptyEnv {
			continue
		}
		s.env[strings.ToLower(key)] = val
	}

	return s
}

// LayerSnapshot captures a read-only snapshot of the Viper instance.
//
// The snapshot contains defaults, file values, currently resolvable bound
// environment variables and explicit overrides. Environment variables are
// read exactly once while the snapshot is being taken; [Snapshot.Trace] and
// [Snapshot.Diff] afterwards never touch the process environment, the
// file system or config watchers.
//
// Mutating the Viper instance after taking the snapshot does not affect it.
func (v *Viper) LayerSnapshot() *Snapshot {
	s := &Snapshot{
		keyDelim:      v.keyDelim,
		aliases:       make(map[string]string, len(v.aliases)),
		defaults:      copyDeepMap(v.defaults),
		file:          copyDeepMap(v.config),
		env:           make(map[string]any),
		autoEnv:       make(map[string]any),
		allowEmptyEnv: v.allowEmptyEnv,
		automaticEnv:  v.automaticEnvApplied,
		override:      copyDeepMap(v.override),
	}

	for alias, key := range v.aliases {
		s.aliases[alias] = key
	}

	// Materialize the bound environment register (including BindEnv aliases).
	for key, envKeys := range v.env {
		for _, envKey := range envKeys {
			if val, ok := v.getEnv(envKey); ok {
				s.env[key] = val
				break
			}
		}
	}

	// With AutomaticEnv, any leaf key known from another layer may be backed
	// by an environment variable. Capture those values once, here.
	if v.automaticEnvApplied {
		known := map[string]bool{}
		known = v.flattenAndMergeMap(known, castMapStringToMapInterface(v.aliases), "")
		known = v.flattenAndMergeMap(known, v.override, "")
		known = v.flattenAndMergeMap(known, v.config, "")
		known = v.flattenAndMergeMap(known, v.kvstore, "")
		known = v.flattenAndMergeMap(known, v.defaults, "")

		envPrefix := strings.Join(v.parents, ".")
		for key := range known {
			envKey := key
			if envPrefix != "" {
				envKey = envPrefix + "." + key
			}
			if _, captured := s.env[key]; captured {
				continue
			}
			if val, ok := v.getEnv(v.mergeWithEnvPrefix(envKey)); ok {
				s.autoEnv[key] = val
			}
		}
	}

	return s
}

func copyDeepMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return copyAndInsensitiviseMap(in)
}

func (s *Snapshot) split(key string) []string {
	return strings.Split(key, s.keyDelim)
}

// realKey resolves an alias chain, mirroring Viper.realKey.
func (s *Snapshot) realKey(key string) string {
	next, ok := s.aliases[key]
	if !ok {
		return key
	}
	return s.realKey(next)
}

// deepFind looks a path up in a nested map. found is true when the exact path
// exists, even when the stored value is nil.
func (s *Snapshot) deepFind(m map[string]any, path []string) (val any, found bool) {
	if len(path) == 0 {
		return m, true
	}
	next, ok := m[path[0]]
	if !ok {
		return nil, false
	}
	if len(path) == 1 {
		return next, true
	}
	switch n := next.(type) {
	case map[any]any:
		return s.deepFind(castToStringMapLocal(n), path[1:])
	case map[string]any:
		return s.deepFind(n, path[1:])
	default:
		return nil, false
	}
}

// findFile mirrors Viper.searchIndexableWithPathPrefixes for the file layer:
// merged path elements (dots inside map keys) take priority over nested
// traversal. The boolean result reports whether the exact path exists, even
// when its value is nil.
func (s *Snapshot) findFile(m map[string]any, path []string) (val any, found bool) {
	if len(path) == 0 {
		return m, true
	}
	for i := len(path); i > 0; i-- {
		prefixKey := strings.Join(path[0:i], s.keyDelim)
		if v, ok := s.findFilePrefix(m, prefixKey, i, path); ok {
			return v, true
		}
	}
	return nil, false
}

func (s *Snapshot) findFilePrefix(m map[string]any, prefixKey string, pathIndex int, path []string) (any, bool) {
	next, ok := m[prefixKey]
	if !ok {
		return nil, false
	}
	if pathIndex == len(path) {
		// Exact path hit, including an explicit null value.
		return next, true
	}
	switch n := next.(type) {
	case map[any]any:
		return s.findFile(castToStringMapLocal(n), path[pathIndex:])
	case map[string]any:
		return s.findFile(n, path[pathIndex:])
	default:
		// A scalar parent cannot satisfy the remaining path elements.
		return nil, false
	}
}

// shadowedInDeepMap mirrors Viper.isPathShadowedInDeepMap: a non-map value at
// a parent path shadows the requested path in lower-priority layers.
func (s *Snapshot) shadowedInDeepMap(path []string, m map[string]any) bool {
	for i := 1; i < len(path); i++ {
		val, found := s.deepFind(m, path[0:i])
		if !found {
			return false
		}
		switch val.(type) {
		case map[any]any, map[string]any:
			continue
		default:
			return true
		}
	}
	return false
}

// shadowedInFlatMap mirrors Viper.isPathShadowedInFlatMap for bound env keys.
func (s *Snapshot) shadowedInFlatMap(path []string, m map[string]any) bool {
	for i := 1; i < len(path); i++ {
		parentKey := strings.Join(path[0:i], s.keyDelim)
		if _, ok := m[parentKey]; ok {
			return true
		}
	}
	return false
}

// Trace resolves a key against the snapshot and reports the contribution of
// every layer plus the effective (winning) value.
//
// Key normalization matches actual reads: the requested key is lower-cased,
// aliases are resolved, nested paths are traversed with the configured
// delimiter and parent values shadow descendants, exactly like [Viper.Get].
//
// The per-layer records describe each layer's own value independently, so the
// report can explain both "what the file held" and "what the effective value
// is" even when a higher-priority layer wins.
func (s *Snapshot) Trace(key string) KeyTrace {
	lkey := strings.ToLower(key)
	path := s.split(lkey)

	trace := KeyTrace{Key: lkey, Layers: map[Layer]LayerValue{}}
	for _, l := range Layers {
		trace.Layers[l] = LayerValue{Layer: l, Presence: PresenceMissing}
	}

	// A nested path shadowed through an alias map behaves like Viper.find.
	if len(path) > 1 {
		if s.shadowedInDeepMap(path, castStringAliasMap(s.aliases)) {
			trace.Key = s.realKey(lkey)
			return trace
		}
	}

	lkey = s.realKey(lkey)
	path = s.split(lkey)
	trace.Key = lkey

	// Record each layer's own contribution independently of higher layers.
	record := func(l Layer, val any, found bool) (Presence, any) {
		if !found {
			return PresenceMissing, nil
		}
		p := presenceFor(val)
		trace.Layers[l] = LayerValue{Layer: l, Presence: p, Value: val}
		return p, val
	}

	ovVal, ovFound := s.deepFind(s.override, path)
	enVal, enFound := s.lookupEnv(lkey)
	fiVal, fiFound := s.findFile(s.file, path)
	deVal, deFound := s.deepFind(s.defaults, path)
	ovP, ovVal := record(LayerOverride, ovVal, ovFound)
	enP, enVal := record(LayerEnv, enVal, enFound)
	fiP, fiVal := record(LayerFile, fiVal, fiFound)
	deP, deVal := record(LayerDefault, deVal, deFound)

	// Resolve the effective value following Viper.find: first non-nil value,
	// respecting the fact that a non-map parent in a higher layer shadows
	// descendants in lower layers.
	switch {
	case ovP == PresenceSet || ovP == PresenceEmpty:
		trace.Effective = LayerOverride
		trace.EffectivePresence = ovP
		trace.EffectiveValue = ovVal
	case s.shadowedInDeepMap(path, s.override):
		// A parent path holds a scalar in the override layer; nothing below
		// it is reachable.
		trace.EffectivePresence = PresenceMissing
	case enP == PresenceSet || enP == PresenceEmpty:
		trace.Effective = LayerEnv
		trace.EffectivePresence = enP
		trace.EffectiveValue = enVal
	case s.shadowedInEnv(path):
		// Bound parent key blocks lower layers.
		trace.EffectivePresence = PresenceMissing
	case fiP == PresenceSet || fiP == PresenceEmpty:
		trace.Effective = LayerFile
		trace.EffectivePresence = fiP
		trace.EffectiveValue = fiVal
	case s.shadowedInDeepMap(path, s.file):
		// Scalar parent in the file layer blocks defaults.
		trace.EffectivePresence = PresenceMissing
	case deP == PresenceSet || deP == PresenceEmpty:
		trace.Effective = LayerDefault
		trace.EffectivePresence = deP
		trace.EffectiveValue = deVal
	default:
		trace.EffectivePresence = PresenceMissing
	}

	return trace
}

// lookupEnv resolves a key from the bound env register and, when AutomaticEnv
// was used, from the captured automatic-env values.
func (s *Snapshot) lookupEnv(lkey string) (any, bool) {
	if val, ok := s.env[lkey]; ok {
		return val, true
	}
	if s.automaticEnv {
		if val, ok := s.autoEnv[lkey]; ok {
			return val, true
		}
	}
	return nil, false
}

// shadowedInEnv reports whether a parent path blocks lower layers in the
// environment registers.
func (s *Snapshot) shadowedInEnv(path []string) bool {
	if s.shadowedInFlatMap(path, s.env) {
		return true
	}
	if s.automaticEnv && s.shadowedInFlatMap(path, s.autoEnv) {
		return true
	}
	return false
}

// Keys enumerates the canonical keys visible in the snapshot. Leaf values
// from all layers are flattened with the configured delimiter, mirroring
// Viper.AllKeys. Alias names are intentionally not emitted twice: lookups
// through aliases resolve to the canonical key.
func (s *Snapshot) Keys() []string {
	set := map[string]bool{}
	collect := func(m map[string]any) {
		flattenKeys(set, m, "", s.keyDelim)
	}
	collect(s.override)
	collect(s.env)
	if s.automaticEnv {
		collect(s.autoEnv)
	}
	collect(s.file)
	collect(s.defaults)

	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func flattenKeys(set map[string]bool, m map[string]any, prefix, delim string) {
	if prefix != "" && set[prefix] {
		return
	}
	var childPrefix string
	if prefix != "" {
		childPrefix = prefix + delim
	}
	for k, val := range m {
		fullKey := childPrefix + strings.ToLower(k)
		switch val.(type) {
		case map[any]any:
			flattenKeys(set, castToStringMapLocal(val.(map[any]any)), fullKey, delim)
		case map[string]any:
			flattenKeys(set, val.(map[string]any), fullKey, delim)
		default:
			set[fullKey] = true
		}
	}
}

func castStringAliasMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func castToStringMapLocal(m map[any]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[fmt.Sprint(k)] = v
	}
	return out
}

// DiffOption configures [Snapshot.Diff].
type DiffOption func(*diffOptions)

type diffOptions struct {
	sensitiveKeys map[string]bool
	sensitiveFunc func(string) bool
}

// DiffSensitiveKeys marks keys as sensitive. Sensitive keys are never
// exported with their values: the report only says whether they changed and
// which layers provided the before/after values.
//
// Keys are canonical (lower-cased, delimiter-joined); alias spellings are
// resolved automatically.
func DiffSensitiveKeys(keys ...string) DiffOption {
	return func(o *diffOptions) {
		if o.sensitiveKeys == nil {
			o.sensitiveKeys = map[string]bool{}
		}
		for _, k := range keys {
			o.sensitiveKeys[strings.ToLower(k)] = true
		}
	}
}

// DiffSensitiveMatcher marks every key for which fn returns true as sensitive.
// The canonical key is passed to fn.
func DiffSensitiveMatcher(fn func(key string) bool) DiffOption {
	return func(o *diffOptions) {
		o.sensitiveFunc = fn
	}
}

// defaultSensitiveMatcher hides obvious secret-bearing keys even when the
// caller forgets to list them explicitly.
func defaultSensitiveMatcher(key string) bool {
	for _, marker := range []string{"password", "passwd", "secret", "token", "apikey", "api-key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

// Change is a single key difference between two snapshots.
type Change struct {
	// Key is the canonical key.
	Key string

	// Changed reports whether the effective value or its source layer changed.
	Changed bool

	// Sensitive is true for keys whose values must not be exported. For
	// sensitive keys only Changed and the source layers are reported.
	Sensitive bool

	// Before/After describe the effective value on each side.
	Before LayerValue
	After  LayerValue

	// BeforeLayers/AfterLayers carry the per-layer presence on each side.
	// For sensitive keys the values inside these records are redacted, but
	// presence and layer are preserved.
	BeforeLayers map[Layer]LayerValue
	AfterLayers  map[Layer]LayerValue
}

// DiffReport is the result of comparing two snapshots.
type DiffReport struct {
	// Changes lists all keys known to either snapshot in canonical order.
	// Unchanged keys are included with Changed == false so the report can
	// explain the provenance of every effective value.
	Changes []Change
}

// Changed returns only the keys that changed, preserving canonical order.
func (r *DiffReport) Changed() []Change {
	var out []Change
	for _, c := range r.Changes {
		if c.Changed {
			out = append(out, c)
		}
	}
	return out
}

// Diff compares two read-only snapshots and reports effective value changes
// together with the layer each value comes from.
//
// The diff is computed purely from the snapshots: the environment and
// configuration files are not re-read and no config watcher is triggered.
//
// Missing, null and empty-string states are compared as distinct states.
// Values are compared with reflect.DeepEqual, so 1 (int) and "1" (string)
// count as a change.
func (s *Snapshot) Diff(after *Snapshot, opts ...DiffOption) *DiffReport {
	o := diffOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	isSensitive := func(key string) bool {
		if o.sensitiveKeys[key] {
			return true
		}
		if o.sensitiveFunc != nil && o.sensitiveFunc(key) {
			return true
		}
		return defaultSensitiveMatcher(key)
	}

	keySet := map[string]bool{}
	for _, k := range s.Keys() {
		keySet[k] = true
	}
	for _, k := range after.Keys() {
		keySet[k] = true
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	report := &DiffReport{Changes: make([]Change, 0, len(keys))}

	for _, key := range keys {
		beforeTrace := s.Trace(key)
		afterTrace := after.Trace(key)

		change := Change{
			Key:          key,
			BeforeLayers: beforeTrace.Layers,
			AfterLayers:  afterTrace.Layers,
		}
		change.Before = LayerValue{
			Layer:    beforeTrace.Effective,
			Presence: beforeTrace.EffectivePresence,
			Value:    beforeTrace.EffectiveValue,
		}
		change.After = LayerValue{
			Layer:    afterTrace.Effective,
			Presence: afterTrace.EffectivePresence,
			Value:    afterTrace.EffectiveValue,
		}

		change.Changed = change.Before.Layer != change.After.Layer ||
			change.Before.Presence != change.After.Presence ||
			!reflect.DeepEqual(change.Before.Value, change.After.Value)

		// When the effective layer/value is unchanged, a sensitive key may
		// still have changed inside a non-winning layer (e.g. a file password
		// was updated but the override keeps winning). Compare the per-layer
		// presence before redacting the values.
		if !change.Changed {
			for _, l := range Layers {
				if change.BeforeLayers[l].Presence != change.AfterLayers[l].Presence {
					change.Changed = true
					break
				}
			}
		}

		if isSensitive(key) {
			change.Sensitive = true
			change.Before = redactLayerValue(change.Before)
			change.After = redactLayerValue(change.After)
			change.BeforeLayers = redactRecords(change.BeforeLayers)
			change.AfterLayers = redactRecords(change.AfterLayers)
		}

		report.Changes = append(report.Changes, change)
	}

	return report
}

func redactLayerValue(l LayerValue) LayerValue {
	if !l.Exists() {
		return l
	}
	l.Value = nil
	if l.Presence != PresenceRedacted {
		l.Presence = PresenceRedacted
	}
	return l
}

func redactRecords(in map[Layer]LayerValue) map[Layer]LayerValue {
	out := make(map[Layer]LayerValue, len(in))
	for l, v := range in {
		out[l] = redactLayerValue(v)
	}
	return out
}

const diagNewline = "\n"

// formatSide renders one side of a change for the human-readable diagnostic:
//
//	layer(presence[=value])
//
// for example: file(set=1), env(set=""), override(empty) or missing.
// Strings are quoted and values are omitted for sensitive keys.
func formatSide(l LayerValue, sensitive bool) string {
	if l.Layer == "" && l.Presence == PresenceMissing {
		return string(PresenceMissing)
	}
	layer := l.Layer
	if layer == "" {
		layer = "-"
	}
	if sensitive || l.Presence == PresenceMissing || l.Presence == PresenceNull || l.Presence == PresenceRedacted {
		return fmt.Sprintf("%s(%s)", layer, presenceName(l.Presence))
	}
	return fmt.Sprintf("%s(%s=%v)", layer, l.Presence, formatValue(l.Value))
}

func presenceName(p Presence) string {
	if p == "" {
		return string(PresenceMissing)
	}
	return string(p)
}

func formatValue(val any) string {
	if _, ok := val.(string); ok {
		return fmt.Sprintf("%q", val)
	}
	return fmt.Sprintf("%v", val)
}

// String renders the diagnostic format used by debugging reports:
//
//	changed:
//	  port: file(set=1) -> env(set=2) [effective: file -> env]
//	  password: override(redacted) -> env(redacted) [sensitive]
//	unchanged:
//	  host: file(set="localhost")
//
// Each line shows the canonical key, both sides as layer(presence[=value]),
// and for changed keys the source-layer transition. Sensitive keys never show
// values; they report redacted presence and the source layers only.
func (r *DiffReport) String() string {
	var changed, unchanged []string
	for _, c := range r.Changes {
		line := fmt.Sprintf("  %s: %s -> %s", c.Key, formatSide(c.Before, c.Sensitive), formatSide(c.After, c.Sensitive))
		if c.Changed {
			line += fmt.Sprintf(" [effective: %s -> %s]", layerName(c.Before.Layer), layerName(c.After.Layer))
		}
		if c.Sensitive {
			line += " [sensitive]"
		}
		if c.Changed {
			changed = append(changed, line)
		} else {
			unchanged = append(unchanged, line)
		}
	}

	var sections []string
	if len(changed) > 0 {
		sections = append(sections, "changed:"+diagNewline+strings.Join(changed, diagNewline))
	}
	if len(unchanged) > 0 {
		sections = append(sections, "unchanged:"+diagNewline+strings.Join(unchanged, diagNewline))
	}
	return strings.Join(sections, diagNewline)
}

func layerName(l Layer) string {
	if l == "" {
		return "-"
	}
	return string(l)
}

// TraceString renders a KeyTrace as a single diagnostic line:
//
//	port: set=2 [effective: env; layers: default(missing) file(set=1) env(set="2") override(missing)]
//
// Sensitive values must be redacted by the caller before printing.
func (t KeyTrace) TraceString() string {
	parts := make([]string, 0, len(Layers))
	for _, l := range Layers {
		parts = append(parts, formatSide(t.Layers[l], false))
	}
	val := string(PresenceMissing)
	if t.EffectivePresence != PresenceMissing {
		val = fmt.Sprintf("%s=%v", t.EffectivePresence, formatValue(t.EffectiveValue))
	}
	return fmt.Sprintf("%s: %s [effective: %s; layers: %s]",
		t.Key, val, layerName(t.Effective), strings.Join(parts, " "))
}
