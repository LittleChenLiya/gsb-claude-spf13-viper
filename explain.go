// Copyright © 2024 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// ExplainSource identifies a configuration source layer, in the order Viper
// consults them when resolving a key.
type ExplainSource string

// Source layers, highest priority first.
const (
	SourceOverride    ExplainSource = "override"     // explicit Set() calls
	SourceFlag        ExplainSource = "flag"         // bound flags that have changed
	SourceEnv         ExplainSource = "env"          // environment variables
	SourceConfig      ExplainSource = "config"       // config file
	SourceKVStore     ExplainSource = "kvstore"      // remote key/value store
	SourceDefault     ExplainSource = "default"      // SetDefault() calls
	SourceFlagDefault ExplainSource = "flag_default" // default value of a bound flag
)

// RedactedValue replaces every value belonging to a sensitive key (or its
// subtree) in an Explanation, including all shadowed candidates.
const RedactedValue = "***REDACTED***"

// ExplainCandidate describes a single source layer's offering for a key.
type ExplainCandidate struct {
	// Source is the layer this candidate comes from.
	Source ExplainSource
	// Found reports whether the layer holds a usable value for the key.
	Found bool
	// Value is a deep copy of the candidate value (redacted for sensitive
	// keys). Mutating it does not affect Viper's internal state.
	Value any
	// Detail identifies the concrete origin, e.g. the environment variable
	// name, the flag name, or the config file path.
	Detail string
	// Shadowed reports whether a higher-priority layer blocks this candidate
	// from winning (e.g. a parent scalar shadowing a nested map).
	Shadowed bool
	// BlockedBy names the higher-priority location that shadows this
	// candidate, in the form "source:parent.key".
	BlockedBy string
	// Note carries extra context, e.g. why an existing value was ignored.
	Note string
}

// Explanation describes how Viper resolves a single key: the canonical key,
// the winning source, the final value, and every shadowed candidate.
//
// All values are deep copies; mutating an Explanation never changes Viper's
// internal configuration.
type Explanation struct {
	// Key is the canonical key: lower-cased and alias-resolved.
	Key string
	// Requested is the key as passed to Explain, lower-cased.
	Requested string
	// AliasChain lists the keys the requested key was resolved through.
	AliasChain []string
	// Found reports whether any source provides a usable value.
	Found bool
	// Source is the winning source layer.
	Source ExplainSource
	// Value is the final value (deep-copied, redacted when sensitive).
	Value any
	// Sensitive reports whether the key matched a sensitive key or subtree.
	Sensitive bool
	// Candidates lists every layer that holds (or nearly holds) a value for
	// the key, in priority order.
	Candidates []ExplainCandidate
}

// String renders a human-readable source chain for the explanation.
func (e Explanation) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "key: %s", e.Key)
	if e.Requested != "" && e.Requested != e.Key {
		fmt.Fprintf(&b, " (requested: %s)", e.Requested)
	}
	if len(e.AliasChain) > 0 {
		fmt.Fprintf(&b, " [alias: %s -> %s]", e.Requested, strings.Join(e.AliasChain, " -> "))
	}
	b.WriteString("\n")

	if e.Sensitive {
		b.WriteString("sensitive: true (values redacted)\n")
	}

	if e.Found {
		fmt.Fprintf(&b, "value: %v (source: %s)\n", e.Value, e.Source)
	} else {
		b.WriteString("value: <not set>\n")
	}

	for _, c := range e.Candidates {
		fmt.Fprintf(&b, "  - %s", c.Source)
		if c.Detail != "" {
			fmt.Fprintf(&b, " [%s]", c.Detail)
		}
		if c.Found {
			fmt.Fprintf(&b, ": %v", c.Value)
		} else {
			b.WriteString(": <no value>")
		}
		if c.Shadowed {
			fmt.Fprintf(&b, " (shadowed by %s)", c.BlockedBy)
		}
		if c.Note != "" {
			fmt.Fprintf(&b, " (%s)", c.Note)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// ExplainOption customizes Explain and ExplainAll.
type ExplainOption func(*explainConfig)

type explainConfig struct {
	sensitiveKeys []string
}

// WithSensitiveKeys marks keys (and their entire subtrees) as sensitive.
// Every candidate value for a sensitive key is redacted in the resulting
// explanations, not just the winning value.
func WithSensitiveKeys(keys ...string) ExplainOption {
	return func(c *explainConfig) {
		c.sensitiveKeys = append(c.sensitiveKeys, keys...)
	}
}

// Explain reports how the global Viper instance resolves key.
func Explain(key string, opts ...ExplainOption) Explanation { return v.Explain(key, opts...) }

// Explain reports how v resolves key: which source wins, what the final
// value is, and which candidates are shadowed.
//
// Explain only inspects in-memory state plus a snapshot of the current
// environment. It never triggers remote reads, file watchers, or decode
// hooks, and the returned data shares no mutable state with v.
func (v *Viper) Explain(key string, opts ...ExplainOption) Explanation {
	cfg := v.newExplainConfig(opts)

	return v.explain(strings.ToLower(key), snapshotEnv(), cfg)
}

// ExplainAll explains every known key of the global Viper instance.
func ExplainAll(opts ...ExplainOption) map[string]Explanation { return v.ExplainAll(opts...) }

// ExplainAll explains every key returned by AllKeys. A single environment
// snapshot is taken and shared by all explanations in the result.
func (v *Viper) ExplainAll(opts ...ExplainOption) map[string]Explanation {
	cfg := v.newExplainConfig(opts)
	snap := snapshotEnv()

	keys := v.AllKeys()
	out := make(map[string]Explanation, len(keys))
	for _, key := range keys {
		out[key] = v.explain(key, snap, cfg)
	}

	return out
}

func (v *Viper) newExplainConfig(opts []ExplainOption) *explainConfig {
	cfg := &explainConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	// Normalize sensitive keys the same way lookup keys are normalized:
	// lower-cased and alias-resolved.
	for i, key := range cfg.sensitiveKeys {
		cfg.sensitiveKeys[i] = v.resolveAlias(strings.ToLower(key))
	}

	return cfg
}

// envSnapshot is a point-in-time copy of the process environment.
type envSnapshot map[string]string

// snapshotEnv captures the current environment. Uppercase aliases are added
// for lookup convenience, mirroring the case-insensitive behavior of
// os.LookupEnv on some platforms.
func snapshotEnv() envSnapshot {
	snap := make(envSnapshot)
	for _, entry := range os.Environ() {
		key, val, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, exists := snap[key]; !exists {
			snap[key] = val
		}
		upper := strings.ToUpper(key)
		if _, exists := snap[upper]; !exists {
			snap[upper] = val
		}
	}

	return snap
}

// lookupEnv mirrors v.getEnv against a snapshot instead of the live
// environment. It reports the raw value, whether the variable exists at all,
// and whether it is usable under the current AllowEmptyEnv policy.
func (v *Viper) lookupEnv(snap envSnapshot, key string) (val string, exists, usable bool) {
	key = v.envKeyName(key)

	val, exists = snap[key]
	usable = exists && (v.allowEmptyEnv || val != "")

	return val, exists, usable
}

// envKeyName applies the configured env key replacer, producing the actual
// environment variable name Viper probes for a key.
func (v *Viper) envKeyName(key string) string {
	if v.envKeyReplacer != nil {
		key = v.envKeyReplacer.Replace(key)
	}

	return key
}

// isPathShadowedInAutoEnvSnapshot is isPathShadowedInAutoEnv evaluated
// against an environment snapshot.
func (v *Viper) isPathShadowedInAutoEnvSnapshot(snap envSnapshot, path []string) string {
	var parentKey string
	for i := 1; i < len(path); i++ {
		parentKey = strings.Join(path[0:i], v.keyDelim)
		if _, _, ok := v.lookupEnv(snap, v.mergeWithEnvPrefix(parentKey)); ok {
			return parentKey
		}
	}

	return ""
}

// resolveAlias follows the alias chain for an already lower-cased key,
// stopping at cycles instead of recursing forever.
func (v *Viper) resolveAlias(lcaseKey string) string {
	visited := map[string]bool{lcaseKey: true}
	current := lcaseKey
	for {
		next, ok := v.aliases[current]
		if !ok || visited[next] {
			return current
		}
		visited[next] = true
		current = next
	}
}

// explain walks the same layers, in the same order, as find, recording a
// candidate per layer instead of returning the first hit.
func (v *Viper) explain(lcaseKey string, snap envSnapshot, cfg *explainConfig) Explanation {
	exp := Explanation{Requested: lcaseKey}

	// Resolve aliases, keeping the chain for the report. Cycle-safe.
	canonical := lcaseKey
	visited := map[string]bool{lcaseKey: true}
	for {
		next, ok := v.aliases[canonical]
		if !ok || visited[next] {
			break
		}
		exp.AliasChain = append(exp.AliasChain, next)
		visited[next] = true
		canonical = next
	}
	exp.Key = canonical
	exp.Sensitive = v.isSensitiveKey(canonical, cfg.sensitiveKeys)

	path := strings.Split(canonical, v.keyDelim)
	nested := len(path) > 1

	// blockedBy, once set, marks every lower-priority candidate as shadowed,
	// mirroring the early returns in find.
	blockedBy := ""

	// An alias can shadow a nested path before any layer is consulted.
	if nested {
		aliasPath := strings.Split(lcaseKey, v.keyDelim)
		if p := v.isPathShadowedInDeepMap(aliasPath, castMapStringToMapInterface(v.aliases)); p != "" {
			blockedBy = "alias:" + p
		}
	}

	redact := func(val any) any {
		if exp.Sensitive {
			return RedactedValue
		}

		return deepCopyValue(val)
	}

	add := func(c ExplainCandidate) {
		if c.Found {
			c.Value = redact(c.Value)
		}
		if blockedBy != "" {
			c.Shadowed = true
			c.BlockedBy = blockedBy
		}
		exp.Candidates = append(exp.Candidates, c)
		if c.Found && !c.Shadowed && !exp.Found {
			exp.Found = true
			exp.Source = c.Source
			exp.Value = c.Value
		}
	}

	// Set() override first.
	if val := v.searchMap(v.override, path); val != nil {
		add(ExplainCandidate{Source: SourceOverride, Found: true, Value: val})
	}
	if nested && blockedBy == "" {
		if p := v.isPathShadowedInDeepMap(path, v.override); p != "" {
			blockedBy = string(SourceOverride) + ":" + p
		}
	}

	// Changed flags next.
	flag, flagExists := v.pflags[canonical]
	if flagExists && flag.HasChanged() {
		add(ExplainCandidate{
			Source: SourceFlag,
			Found:  true,
			Value:  flagToValue(flag),
			Detail: "--" + flag.Name(),
		})
	}
	if nested && blockedBy == "" {
		if p := v.isPathShadowedInFlatMap(path, v.pflags); p != "" {
			blockedBy = string(SourceFlag) + ":" + p
		}
	}

	// Environment next: automatic env first, then explicitly bound vars.
	if v.automaticEnvApplied {
		envKey := strings.Join(append(slices.Clone(v.parents), canonical), ".")
		name := v.mergeWithEnvPrefix(envKey)
		val, exists, usable := v.lookupEnv(snap, name)
		switch {
		case usable:
			add(ExplainCandidate{Source: SourceEnv, Found: true, Value: val, Detail: v.envKeyName(name)})
		case exists:
			add(ExplainCandidate{
				Source: SourceEnv,
				Detail: v.envKeyName(name),
				Note:   "empty value ignored: AllowEmptyEnv is false",
			})
		}
		if nested && blockedBy == "" {
			if p := v.isPathShadowedInAutoEnvSnapshot(snap, path); p != "" {
				blockedBy = string(SourceEnv) + ":" + p
			}
		}
	}
	for _, envkey := range v.env[canonical] {
		val, exists, usable := v.lookupEnv(snap, envkey)
		switch {
		case usable:
			add(ExplainCandidate{Source: SourceEnv, Found: true, Value: val, Detail: v.envKeyName(envkey)})
		case exists:
			add(ExplainCandidate{
				Source: SourceEnv,
				Detail: v.envKeyName(envkey),
				Note:   "empty value ignored: AllowEmptyEnv is false",
			})
		}
	}
	if nested && blockedBy == "" {
		if p := v.isPathShadowedInFlatMap(path, v.env); p != "" {
			blockedBy = string(SourceEnv) + ":" + p
		}
	}

	// Config file next. The indexable search also resolves keys that
	// literally contain the key delimiter (e.g. "foo.bar" in the file).
	if val := v.searchIndexableWithPathPrefixes(v.config, path); val != nil {
		add(ExplainCandidate{Source: SourceConfig, Found: true, Value: val, Detail: v.configFile})
	}
	if nested && blockedBy == "" {
		if p := v.isPathShadowedInDeepMap(path, v.config); p != "" {
			blockedBy = string(SourceConfig) + ":" + p
		}
	}

	// K/V store next.
	if val := v.searchMap(v.kvstore, path); val != nil {
		add(ExplainCandidate{Source: SourceKVStore, Found: true, Value: val})
	}
	if nested && blockedBy == "" {
		if p := v.isPathShadowedInDeepMap(path, v.kvstore); p != "" {
			blockedBy = string(SourceKVStore) + ":" + p
		}
	}

	// Defaults next.
	if val := v.searchMap(v.defaults, path); val != nil {
		add(ExplainCandidate{Source: SourceDefault, Found: true, Value: val})
	}
	if nested && blockedBy == "" {
		if p := v.isPathShadowedInDeepMap(path, v.defaults); p != "" {
			blockedBy = string(SourceDefault) + ":" + p
		}
	}

	// Last chance, mirroring find(lcaseKey, true): the default value of a
	// bound flag that has not changed.
	if flagExists && !flag.HasChanged() {
		add(ExplainCandidate{
			Source: SourceFlagDefault,
			Found:  true,
			Value:  flagToValue(flag),
			Detail: "--" + flag.Name() + " (default)",
		})
	}

	return exp
}

// isSensitiveKey reports whether canonical is a sensitive key, lives inside
// a sensitive subtree, or is a parent of one (in which case its value
// contains the sensitive subtree and must be redacted as a whole).
func (v *Viper) isSensitiveKey(canonical string, sensitiveKeys []string) bool {
	for _, key := range sensitiveKeys {
		if canonical == key ||
			strings.HasPrefix(canonical, key+v.keyDelim) ||
			strings.HasPrefix(key, canonical+v.keyDelim) {
			return true
		}
	}

	return false
}

// deepCopyValue copies maps and slices so returned explanations share no
// mutable state with Viper's internal registries.
func deepCopyValue(val any) any {
	switch t := val.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, item := range t {
			m[k] = deepCopyValue(item)
		}

		return m
	case map[any]any:
		m := make(map[any]any, len(t))
		for k, item := range t {
			m[k] = deepCopyValue(item)
		}

		return m
	case []any:
		s := make([]any, len(t))
		for i, item := range t {
			s[i] = deepCopyValue(item)
		}

		return s
	case []string:
		return slices.Clone(t)
	case []int:
		return slices.Clone(t)
	default:
		return val
	}
}
