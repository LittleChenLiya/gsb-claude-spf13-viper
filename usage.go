package viper

import (
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/cast"
)

// TrackUsage enables tracking of which keys present in the configuration
// have actually been read through Get, the typed Get helpers or one of the
// Unmarshal functions.
//
// Diagnostic accessors such as IsSet, AllKeys, AllSettings and DebugTo do not
// mark keys as used. Use [Viper.UnusedKeys] to report the keys that were never
// read and [Viper.ResetUsage] to clear the record.
func TrackUsage() Option {
	return optionFunc(func(v *Viper) {
		v.EnableUsageTracking()
	})
}

// EnableUsageTracking turns on usage tracking for this Viper instance.
// Keys read before tracking was enabled are not recorded retroactively.
func EnableUsageTracking() { v.EnableUsageTracking() }

// EnableUsageTracking turns on usage tracking for this Viper instance.
// Keys read before tracking was enabled are not recorded retroactively.
func (v *Viper) EnableUsageTracking() {
	if v.usage == nil {
		v.usage = newUsageTracker()
	}
}

// ResetUsage clears the record of keys that were read without disabling
// usage tracking itself. It is mainly useful in tests or after reloading the
// configuration.
func ResetUsage() { v.ResetUsage() }

// ResetUsage clears the record of keys that were read without disabling
// usage tracking itself. It is mainly useful in tests or after reloading the
// configuration.
func (v *Viper) ResetUsage() {
	if v.usage == nil {
		return
	}
	v.usage.reset()
}

// UnusedKeys returns the configuration keys that have never been read since
// tracking was enabled (or since the last [Viper.ResetUsage] call). The keys
// are normalized the same way Viper normalizes keys: lower-cased, resolved
// through aliases and joined with the configured key delimiter.
//
// Reading a parent key (for example a map or the subtree passed to
// UnmarshalKey) also marks all of its descendant keys as used.
//
// The returned list is sorted and calling this method does not mark any key
// as used. It returns nil when usage tracking is disabled.
func UnusedKeys() []string { return v.UnusedKeys() }

// UnusedKeys returns the configuration keys that have never been read since
// tracking was enabled (or since the last [Viper.ResetUsage] call). The keys
// are normalized the same way Viper normalizes keys: lower-cased, resolved
// through aliases and joined with the configured key delimiter.
//
// Reading a parent key (for example a map or the subtree passed to
// UnmarshalKey) also marks all of its descendant keys as used.
//
// The returned list is sorted and calling this method does not mark any key
// as used. It returns nil when usage tracking is disabled.
func (v *Viper) UnusedKeys() []string {
	root := v.usageRoot()
	if root == nil {
		return nil
	}

	used := root.usedSnapshot()
	prefixPath := v.usagePath()
	prefix := strings.Join(prefixPath, v.keyDelim)

	var unused []string
	v.flattenConfigLeaves(v.config, v.usagePath(), func(key string) {
		if !used[key] {
			if prefix != "" {
				key = strings.TrimPrefix(key, prefix+v.keyDelim)
			}
			unused = append(unused, key)
		}
	})

	sort.Strings(unused)
	return unused
}

// usageTracker stores the fully resolved leaf keys that were read.
type usageTracker struct {
	used map[string]bool
}

func newUsageTracker() *usageTracker {
	return &usageTracker{used: make(map[string]bool)}
}

func (t *usageTracker) mark(key string) {
	if key == "" {
		return
	}
	t.used[key] = true
}

func (t *usageTracker) reset() {
	t.used = make(map[string]bool)
}

func (t *usageTracker) usedSnapshot() map[string]bool {
	snapshot := make(map[string]bool, len(t.used))
	for key := range t.used {
		snapshot[key] = true
	}
	return snapshot
}

// usageRoot returns the tracker shared by a Viper and all of its sub Vipers.
func (v *Viper) usageRoot() *usageTracker {
	if v == nil {
		return nil
	}
	if v.usage != nil {
		return v.usage
	}
	if v.root != nil {
		return v.root.usageRoot()
	}
	return nil
}

// joinUsageKey prefixes a key resolved on this Viper with its parent path.
func (v *Viper) joinUsageKey(lcaseKey string) string {
	prefix := v.usagePath()
	if lcaseKey == "" {
		return strings.Join(prefix, v.keyDelim)
	}
	if len(prefix) == 0 {
		return lcaseKey
	}
	return strings.Join(prefix, v.keyDelim) + v.keyDelim + lcaseKey
}

// usagePath returns the canonical position of this Viper inside the root
// configuration. Sub Vipers resolve aliases here without touching parents,
// which keeps driving the environment variable lookup.
func (v *Viper) usagePath() []string {
	if len(v.usagePrefix) > 0 {
		return v.usagePrefix
	}
	return v.parents
}

// trackRead records a direct read of key. If the resolved value is a map,
// every key below it is recorded as well, because reading the map exposes the
// whole subtree to the caller.
func (v *Viper) trackRead(key string, val any) {
	tracker := v.usageRoot()
	if tracker == nil {
		return
	}

	lcaseKey := strings.ToLower(key)
	lcaseKey = v.realKey(lcaseKey)
	fullKey := v.joinUsageKey(lcaseKey)

	switch data := val.(type) {
	case map[string]any:
		v.flattenConfigLeaves(data, splitUsagePath(fullKey, v.keyDelim), tracker.mark)
	case map[any]any:
		v.flattenConfigLeaves(cast.ToStringMap(data), splitUsagePath(fullKey, v.keyDelim), tracker.mark)
	default:
		tracker.mark(fullKey)
	}
}

// trackUnmarshal records the keys that mapstructure actually decoded. prefix
// is the path the unmarshalled value was read from (empty for a full
// unmarshal).
func (v *Viper) trackUnmarshal(prefix string, metadata *mapstructure.Metadata, val any, leaves map[string]bool) {
	tracker := v.usageRoot()
	if tracker == nil {
		return
	}

	lcasePrefix := strings.ToLower(prefix)
	lcasePrefix = v.realKey(lcasePrefix)
	parent := v.joinUsageKey(lcasePrefix)
	parentPath := splitUsagePath(parent, v.keyDelim)

	// mapstructure emits "name[k]" metadata keys when decoding into a Go map.
	// Only such map destinations expose an entire configuration subtree;
	// intermediate keys of nested structs do not.
	mapPrefixes := make(map[string]bool)
	for _, key := range metadata.Keys {
		if idx := strings.IndexByte(key, '['); idx >= 0 {
			mapPrefixes[key[:idx]] = true
		}
	}

	rootConsumed := false
	for _, key := range metadata.Keys {
		if strings.HasPrefix(key, "[") {
			rootConsumed = true
			continue
		}
		if strings.ContainsRune(key, '[') {
			continue
		}
		parts := splitUsagePath(key, ".")
		fullPath := make([]string, 0, len(parentPath)+len(parts))
		fullPath = append(fullPath, parentPath...)
		fullPath = append(fullPath, parts...)
		full := v.realKey(strings.Join(fullPath, v.keyDelim))

		switch {
		case leaves[full]:
			tracker.mark(full)
		case mapPrefixes[key]:
			if subtree, ok := lookupConfigSubtree(cast.ToStringMap(val), parts); ok {
				v.flattenConfigLeaves(subtree, fullPath, tracker.mark)
			}
		}
	}

	// The unmarshalled value itself was decoded into a map.
	if rootConsumed {
		v.flattenConfigLeaves(cast.ToStringMap(val), parentPath, tracker.mark)
	}
}

// lookupConfigSubtree returns the nested map found at path inside data.
func lookupConfigSubtree(data map[string]any, path []string) (map[string]any, bool) {
	current := data
	for _, part := range path {
		next, ok := current[part]
		if !ok {
			return nil, false
		}
		current = cast.ToStringMap(next)
		if current == nil {
			return nil, false
		}
	}
	return current, true
}

func splitUsagePath(key, delim string) []string {
	if key == "" {
		return nil
	}
	return strings.Split(key, delim)
}

// flattenConfigLeaves invokes visit for every leaf path in m. Prefix is the
// normalized path of m itself.
func (v *Viper) flattenConfigLeaves(m map[string]any, prefix []string, visit func(string)) {
	for key, val := range m {
		path := append(append([]string{}, prefix...), strings.ToLower(key))
		switch data := val.(type) {
		case map[string]any:
			v.flattenConfigLeaves(data, path, visit)
		case map[any]any:
			v.flattenConfigLeaves(cast.ToStringMap(data), path, visit)
		default:
			visit(strings.Join(path, v.keyDelim))
		}
	}
}

// usageConfigLeaves returns the set of all leaf keys currently in the
// configuration, rooted at this Viper's canonical usage path.
func (v *Viper) usageConfigLeaves() map[string]bool {
	leaves := make(map[string]bool)
	v.flattenConfigLeaves(v.config, v.usagePath(), func(key string) {
		leaves[key] = true
	})
	return leaves
}
