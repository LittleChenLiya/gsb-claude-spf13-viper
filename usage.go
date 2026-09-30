// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/cast"
)

// usage records configuration keys that have been read through one of the
// Viper read APIs (Get, the typed Get helpers, Unmarshal and UnmarshalKey).
//
// Keys are stored using Viper's own normalization: lower-cased, aliases are
// resolved, and reads from a Viper returned by Sub are stored with the
// parent prefix. Reading a key marks the whole subtree below the key as used.
type usage struct {
	mu   sync.RWMutex
	used map[string]bool
}

func newUsage() *usage {
	return &usage{used: make(map[string]bool)}
}

func (u *usage) mark(key string) {
	if u == nil || key == "" {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.used[key] = true
}

func (u *usage) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.used = make(map[string]bool)
}

// covers reports whether the given leaf key is identical to a recorded key or
// lives below it.
func (u *usage) covers(key string, delim string) bool {
	if u == nil {
		return false
	}

	u.mu.RLock()
	defer u.mu.RUnlock()

	for usedKey := range u.used {
		if usedKey == key || strings.HasPrefix(key, usedKey+delim) {
			return true
		}
	}

	return false
}

// configLeafKeys returns the lower-cased leaf keys of the config file map,
// joined with the key delimiter.
func configLeafKeys(config map[string]any, delim string) []string {
	leaves := flattenConfig(config, "", delim, nil)
	sort.Strings(leaves)

	return leaves
}

func flattenConfig(m map[string]any, prefix, delim string, leaves []string) []string {
	if prefix != "" {
		prefix += delim
	}

	for key, value := range m {
		fullKey := prefix + strings.ToLower(key)
		switch value := value.(type) {
		case map[string]any:
			leaves = flattenConfig(value, fullKey, delim, leaves)
		case map[any]any:
			leaves = flattenConfig(cast.ToStringMap(value), fullKey, delim, leaves)
		default:
			leaves = append(leaves, fullKey)
		}
	}

	return leaves
}

// WithUsageTracking enables tracking of configuration key reads.
//
// When tracking is enabled, [Viper.UnusedKeys] reports the keys present in the
// loaded configuration that have never been read through Get, one of the
// typed Get helpers, Unmarshal or UnmarshalKey. Diagnostic methods such as
// IsSet, AllKeys and AllSettings do not consume keys, and neither does
// [Viper.UnusedKeys] itself.
//
// Sub Vipers created from a tracked Viper share the tracking state: a read on
// a Sub Viper is attributed to the corresponding key of the parent Viper.
func WithUsageTracking() Option {
	return optionFunc(func(v *Viper) {
		v.EnableUsageTracking()
	})
}

// EnableUsageTracking turns on tracking of configuration key reads.
// Tracking starts empty: keys read before it is enabled are not recorded.
func (v *Viper) EnableUsageTracking() {
	v.usageMu.Lock()
	defer v.usageMu.Unlock()

	if v.usage == nil {
		v.usage = newUsage()
	}
}

// DisableUsageTracking turns off tracking of configuration key reads.
// The recorded usage information is discarded.
func (v *Viper) DisableUsageTracking() {
	v.usageMu.Lock()
	defer v.usageMu.Unlock()

	v.usage = nil
}

// ResetUsage clears the recorded configuration key reads without changing the
// loaded configuration. Tracking remains enabled.
func (v *Viper) ResetUsage() {
	v.usageMu.RLock()
	u := v.usage
	v.usageMu.RUnlock()

	u.reset()
}

// UnusedKeys returns the keys present in the loaded configuration that have
// never been read.
//
// Keys are normalized the same way Viper normalizes its own keys: lower-cased
// and resolved through registered aliases. Reading a parent key (for example
// with GetStringMap or UnmarshalKey) marks every key below it as used.
//
// The returned keys are sorted lexicographically. Calling UnusedKeys does not
// mark anything as used, so repeated calls return the same result. If usage
// tracking is not enabled, UnusedKeys returns nil.
func (v *Viper) UnusedKeys() []string {
	v.usageMu.RLock()
	u := v.usage
	v.usageMu.RUnlock()

	if u == nil {
		return nil
	}

	var unused []string

	for _, key := range configLeafKeys(v.config, v.keyDelim) {
		rootKey := v.fullKey(key)

		if !u.covers(rootKey, v.keyDelim) {
			unused = append(unused, key)
		}
	}

	return unused
}

// UsageTrackingEnabled reports whether read tracking is enabled.
func (v *Viper) UsageTrackingEnabled() bool {
	v.usageMu.RLock()
	defer v.usageMu.RUnlock()

	return v.usage != nil
}

// markUsage records a read of key, resolving aliases and adding the Sub Viper
// parent prefix. The key is expected to be lower-cased already.
func (v *Viper) markUsage(lcaseKey string) {
	v.usageMu.RLock()
	u := v.usage
	v.usageMu.RUnlock()

	if u == nil {
		return
	}

	key := v.realKey(lcaseKey)
	if len(v.parents) > 0 {
		key = strings.Join(append(append([]string{}, v.parents...), key), v.keyDelim)
	}

	u.mark(key)
}

// markUnmarshalUsage records the keys consumed by an Unmarshal call.
//
// Keys successfully decoded into a struct are taken from the decoder
// metadata, so a struct that does not declare a field does not consume the
// corresponding configuration key. Decoding into a map (or any non-struct
// type) consumes the whole subtree below the unmarshalled key.
func (v *Viper) markUnmarshalUsage(lcaseKey string, rawVal any, metadata *mapstructure.Metadata) {
	v.usageMu.RLock()
	u := v.usage
	v.usageMu.RUnlock()

	if u == nil {
		return
	}

	prefix := v.fullKey(lcaseKey)

	if !isStructDestination(rawVal) {
		if prefix != "" {
			u.mark(prefix)
		}

		return
	}

	if metadata == nil {
		if prefix != "" {
			u.mark(prefix)
		}

		return
	}

	for _, decodedKey := range v.deepestKeys(metadata.Keys) {
		key := strings.ReplaceAll(decodedKey, ".", v.keyDelim)
		if prefix != "" {
			key = prefix + v.keyDelim + key
		}
		if key != "" {
			u.mark(key)
		}
	}
}

// deepestKeys drops decoded keys that are strict prefixes of another decoded
// key. mapstructure records intermediate structs in Metadata.Keys, but only
// leaf fields should consume a configuration key; otherwise a parent key would
// hide unrelated keys below it.
func (v *Viper) deepestKeys(keys []string) []string {
	var deepest []string

	for _, candidate := range keys {
		shallow := false
		for _, other := range keys {
			if other != candidate && strings.HasPrefix(other, candidate+".") {
				shallow = true
				break
			}
		}

		if !shallow {
			deepest = append(deepest, candidate)
		}
	}

	return deepest
}

// fullKey resolves aliases and prepends the Sub Viper parent prefix.
func (v *Viper) fullKey(lcaseKey string) string {
	key := v.realKey(lcaseKey)
	if len(v.parents) > 0 {
		if key == "" {
			return strings.Join(v.parents, v.keyDelim)
		}

		key = strings.Join(append(append([]string{}, v.parents...), key), v.keyDelim)
	}

	return key
}

func isStructDestination(rawVal any) bool {
	rv := reflect.ValueOf(rawVal)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}

	return rv.Kind() == reflect.Struct
}

// EnableUsageTracking turns on tracking of configuration key reads on the
// global Viper instance.
func EnableUsageTracking() { v.EnableUsageTracking() }

// DisableUsageTracking turns off tracking of configuration key reads on the
// global Viper instance.
func DisableUsageTracking() { v.DisableUsageTracking() }

// ResetUsage clears the recorded configuration key reads on the global Viper
// instance without changing the loaded configuration.
func ResetUsage() { v.ResetUsage() }

// UnusedKeys returns the keys present in the loaded configuration of the
// global Viper instance that have never been read. The keys are sorted
// lexicographically, and calling this function does not mark them as used.
func UnusedKeys() []string { return v.UnusedKeys() }
