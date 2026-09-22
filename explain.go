// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"os"
	"strings"
)

// Source identifies a configuration source layer, in Viper's priority order.
type Source string

// Configuration sources, highest priority first.
const (
	SourceOverride    Source = "override"    // explicit Set() calls
	SourceFlag        Source = "flag"        // bound flags that have changed
	SourceEnv         Source = "env"         // environment variables
	SourceConfig      Source = "config"      // config file
	SourceKVStore     Source = "kvstore"     // remote key/value store
	SourceDefault     Source = "default"     // SetDefault() calls
	SourceFlagDefault Source = "flagDefault" // default value of an unchanged bound flag
	SourceAlias       Source = "alias"       // alias registry (only used to report shadowing)
)

// maskedValue replaces the values of sensitive keys in explanations.
const maskedValue = "***"

// Candidate is a single source's offering for a key, recorded by Explain.
type Candidate struct {
	// Source is the configuration layer this candidate comes from.
	Source Source `json:"source"`
	// Key is the lookup key within the source: the canonical key for map
	// based sources, the flag name for flags, or the environment variable
	// name (after the env key replacer) for env sources.
	Key string `json:"key"`
	// Value is a deep copy of the candidate value. It is replaced by a mask
	// when the explained key is marked sensitive.
	Value any `json:"value"`
	// Masked reports whether Value was masked because the key is sensitive.
	Masked bool `json:"masked,omitempty"`
	// Winner reports whether this candidate provides the effective value.
	Winner bool `json:"winner,omitempty"`
	// BlockedBy is the canonical path of a parent scalar in a higher
	// priority source that shadows this candidate, if any.
	BlockedBy string `json:"blockedBy,omitempty"`
	// BlockedAt is the source holding the blocking parent scalar, if any.
	BlockedAt Source `json:"blockedAt,omitempty"`
}

// Explanation describes how Viper resolves a single key: the canonical key,
// the winning source, the effective value, and every shadowed candidate.
//
// All values are deep copies; mutating an Explanation never affects the
// Viper instance it came from.
type Explanation struct {
	// RequestedKey is the key as passed to Explain (lowercased).
	RequestedKey string `json:"requestedKey"`
	// Key is the canonical key after alias resolution and case
	// normalization.
	Key string `json:"key"`
	// AliasChain lists the aliases followed to reach Key, starting with the
	// requested key. It is empty when no alias was involved.
	AliasChain []string `json:"aliasChain,omitempty"`
	// AliasCycle reports that alias resolution hit a cycle and was aborted.
	AliasCycle bool `json:"aliasCycle,omitempty"`
	// Set reports whether any source provides a value for the key.
	Set bool `json:"set"`
	// Source is the winning source. Empty when the key is not set.
	Source Source `json:"source,omitempty"`
	// Value is the effective value (a deep copy, masked when sensitive).
	Value any `json:"value,omitempty"`
	// Candidates lists every source offering a value, in priority order.
	Candidates []Candidate `json:"candidates,omitempty"`
	// BlockedBy is the canonical path of a parent scalar that shadows the
	// key (e.g. "app" when a scalar "app" blocks "app.port"), if any.
	BlockedBy string `json:"blockedBy,omitempty"`
	// BlockedAt is the source holding the blocking parent scalar, if any.
	BlockedAt Source `json:"blockedAt,omitempty"`
}

// ExplainOption customizes Explain and ExplainAll.
type ExplainOption func(*explainOptions)

type explainOptions struct {
	sensitive []string
}

// WithSensitiveKeys marks keys (and their whole subtree) as sensitive: every
// candidate value for those keys is masked in the explanation, not just the
// winning value. Keys are case-insensitive and use the configured key
// delimiter for nesting.
func WithSensitiveKeys(keys ...string) ExplainOption {
	return func(o *explainOptions) {
		o.sensitive = append(o.sensitive, keys...)
	}
}

func (v *Viper) newExplainOptions(opts []ExplainOption) *explainOptions {
	o := &explainOptions{}
	for _, opt := range opts {
		opt(o)
	}
	// Normalize sensitive keys the same way explained keys are normalized.
	normalized := make([]string, 0, len(o.sensitive))
	for _, key := range o.sensitive {
		_, realKey, _ := v.resolveAliasChain(strings.ToLower(key))
		normalized = append(normalized, realKey)
	}
	o.sensitive = normalized

	return o
}

// isSensitive reports whether key is, contains, or is contained in a
// sensitive subtree.
func (o *explainOptions) isSensitive(delim, key string) bool {
	for _, s := range o.sensitive {
		if key == s ||
			strings.HasPrefix(key, s+delim) ||
			strings.HasPrefix(s, key+delim) {
			return true
		}
	}

	return false
}

// Explain returns an Explanation describing how the given key resolves:
// which source wins, the effective value, and all shadowed candidates.
//
// The environment is read from a snapshot taken at call time. Explain never
// triggers remote reads, config watchers, or decoding hooks.
func Explain(key string, opts ...ExplainOption) *Explanation { return v.Explain(key, opts...) }

// Explain returns an Explanation describing how the given key resolves:
// which source wins, the effective value, and all shadowed candidates.
//
// The environment is read from a snapshot taken at call time. Explain never
// triggers remote reads, config watchers, or decoding hooks.
func (v *Viper) Explain(key string, opts ...ExplainOption) *Explanation {
	return v.explain(strings.ToLower(key), true, snapshotEnv(), v.newExplainOptions(opts))
}

// ExplainAll explains every key known to Viper (see AllKeys) and returns the
// explanations keyed by canonical key. All explanations share a single
// environment snapshot taken at call time.
func ExplainAll(opts ...ExplainOption) map[string]*Explanation { return v.ExplainAll(opts...) }

// ExplainAll explains every key known to Viper (see AllKeys) and returns the
// explanations keyed by canonical key. All explanations share a single
// environment snapshot taken at call time.
func (v *Viper) ExplainAll(opts ...ExplainOption) map[string]*Explanation {
	o := v.newExplainOptions(opts)
	snapshot := snapshotEnv()

	explanations := make(map[string]*Explanation)
	for _, key := range v.AllKeys() {
		explanations[key] = v.explain(key, true, snapshot, o)
	}

	return explanations
}

// snapshotEnv captures the current process environment and returns a lookup
// function over that immutable snapshot.
func snapshotEnv() func(string) (string, bool) {
	env := os.Environ()
	snapshot := make(map[string]string, len(env))
	for _, entry := range env {
		if i := strings.Index(entry, "="); i >= 0 {
			snapshot[entry[:i]] = entry[i+1:]
		}
	}

	return func(key string) (string, bool) {
		val, ok := snapshot[key]
		return val, ok
	}
}

// resolveAliasChain follows the alias registry iteratively, protecting
// against cycles. It returns the chain of keys visited (starting with key)
// and the final real key.
func (v *Viper) resolveAliasChain(key string) (chain []string, realKey string, cycle bool) {
	seen := map[string]bool{key: true}
	realKey = key
	for {
		next, exists := v.aliases[realKey]
		if !exists {
			return chain, realKey, false
		}
		chain = append(chain, realKey)
		if seen[next] {
			return append(chain, next), next, true
		}
		seen[next] = true
		realKey = next
	}
}

// explain mirrors the lookup logic of find(), recording every candidate
// instead of returning the first match. It reuses the same search and
// shadowing helpers so the reported priority always matches actual lookups.
func (v *Viper) explain(lcaseKey string, flagDefault bool, envLookup func(string) (string, bool), opts *explainOptions) *Explanation {
	exp := &Explanation{RequestedKey: lcaseKey, Key: lcaseKey}

	path := strings.Split(lcaseKey, v.keyDelim)
	nested := len(path) > 1

	blocked := false
	block := func(at Source, by string) {
		if !blocked {
			blocked = true
			exp.BlockedAt = at
			exp.BlockedBy = by
		}
	}

	// Aliases shadow nested paths below them.
	if nested {
		if p := v.isPathShadowedInDeepMap(path, castMapStringToMapInterface(v.aliases)); p != "" {
			block(SourceAlias, p)
		}
	}

	// Resolve aliases (cycle-safe).
	chain, realKey, cycle := v.resolveAliasChain(lcaseKey)
	if cycle {
		exp.AliasChain = chain
		exp.AliasCycle = true

		return exp
	}
	if len(chain) > 0 {
		exp.AliasChain = append(chain, realKey)
	}
	lcaseKey = realKey
	exp.Key = lcaseKey
	path = strings.Split(lcaseKey, v.keyDelim)
	nested = len(path) > 1

	sensitive := opts.isSensitive(v.keyDelim, lcaseKey)

	winnerFound := false
	add := func(source Source, key string, val any) {
		candidate := Candidate{Source: source, Key: key, Value: deepCopyValue(val)}
		if sensitive {
			candidate.Value = maskedValue
			candidate.Masked = true
		}
		switch {
		case blocked:
			candidate.BlockedBy = exp.BlockedBy
			candidate.BlockedAt = exp.BlockedAt
		case !winnerFound:
			candidate.Winner = true
			winnerFound = true
			exp.Set = true
			exp.Source = source
			exp.Value = candidate.Value
		}
		exp.Candidates = append(exp.Candidates, candidate)
	}

	// Set() override first
	if val := v.searchMap(v.override, path); val != nil {
		add(SourceOverride, lcaseKey, val)
	}
	if nested && !winnerFound {
		if p := v.isPathShadowedInDeepMap(path, v.override); p != "" {
			block(SourceOverride, p)
		}
	}

	// PFlag override next
	if flag, exists := v.pflags[lcaseKey]; exists && flag.HasChanged() {
		add(SourceFlag, flag.Name(), flagValue(flag))
	}
	if nested && !winnerFound {
		if p := v.isPathShadowedInFlatMap(path, v.pflags); p != "" {
			block(SourceFlag, p)
		}
	}

	// Env override next
	if v.automaticEnvApplied {
		envKey := strings.Join(append(v.parents, lcaseKey), ".")
		merged := v.mergeWithEnvPrefix(envKey)
		if val, ok := v.getEnvWith(merged, envLookup); ok {
			add(SourceEnv, v.envVarName(merged), val)
		}
		if nested && !winnerFound {
			if p := v.isPathShadowedInAutoEnvWith(path, envLookup); p != "" {
				block(SourceEnv, p)
			}
		}
	}
	if envkeys, exists := v.env[lcaseKey]; exists {
		for _, envkey := range envkeys {
			if val, ok := v.getEnvWith(envkey, envLookup); ok {
				add(SourceEnv, v.envVarName(envkey), val)
			}
		}
	}
	if nested && !winnerFound {
		if p := v.isPathShadowedInFlatMap(path, v.env); p != "" {
			block(SourceEnv, p)
		}
	}

	// Config file next
	if val := v.searchIndexableWithPathPrefixes(v.config, path); val != nil {
		add(SourceConfig, lcaseKey, val)
	}
	if nested && !winnerFound {
		if p := v.isPathShadowedInDeepMap(path, v.config); p != "" {
			block(SourceConfig, p)
		}
	}

	// K/V store next
	if val := v.searchMap(v.kvstore, path); val != nil {
		add(SourceKVStore, lcaseKey, val)
	}
	if nested && !winnerFound {
		if p := v.isPathShadowedInDeepMap(path, v.kvstore); p != "" {
			block(SourceKVStore, p)
		}
	}

	// Default next
	if val := v.searchMap(v.defaults, path); val != nil {
		add(SourceDefault, lcaseKey, val)
	}
	if nested && !winnerFound {
		if p := v.isPathShadowedInDeepMap(path, v.defaults); p != "" {
			block(SourceDefault, p)
		}
	}

	if flagDefault && !winnerFound && !blocked {
		// last chance: the flag's default value, mirroring find()
		if flag, exists := v.pflags[lcaseKey]; exists {
			add(SourceFlagDefault, flag.Name(), flagValue(flag))
		}
	}

	return exp
}

// deepCopyValue returns a copy of val that shares no mutable state with the
// original, so explanations never alias Viper's internal configuration.
func deepCopyValue(val any) any {
	switch val := val.(type) {
	case map[string]any:
		copied := make(map[string]any, len(val))
		for k, item := range val {
			copied[k] = deepCopyValue(item)
		}

		return copied
	case map[any]any:
		copied := make(map[any]any, len(val))
		for k, item := range val {
			copied[k] = deepCopyValue(item)
		}

		return copied
	case []any:
		copied := make([]any, len(val))
		for i, item := range val {
			copied[i] = deepCopyValue(item)
		}

		return copied
	default:
		return val
	}
}
