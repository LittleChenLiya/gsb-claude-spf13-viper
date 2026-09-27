package viper

import (
	"reflect"
	"sort"
	"strings"
	"sync"
)

// ChangeKind describes the kind of a single key change between two committed
// configuration snapshots.
type ChangeKind int

const (
	// ChangeAdded indicates the key is present in the new snapshot but was
	// missing from the previous one.
	ChangeAdded ChangeKind = iota + 1
	// ChangeRemoved indicates the key was present in the previous snapshot
	// but is missing from the new one.
	ChangeRemoved
	// ChangeUpdated indicates the key is present in both snapshots but its
	// effective value changed.
	ChangeUpdated
)

// String returns a human-readable representation of the change kind.
func (k ChangeKind) String() string {
	switch k {
	case ChangeAdded:
		return "added"
	case ChangeRemoved:
		return "removed"
	case ChangeUpdated:
		return "updated"
	default:
		return "unknown"
	}
}

// KeyChange describes a single changed key path. It intentionally does not
// carry the old or new value: notifications are value-free by default.
type KeyChange struct {
	// Path is the normalized (lowercase, delimiter-separated) key path.
	Path string
	// Kind describes whether the key was added, removed or updated.
	Kind ChangeKind
}

// ChangeEvent is delivered to subscribers whose subscription path overlaps
// with at least one changed path of a commit.
type ChangeEvent struct {
	// Version is the version of the newly published configuration snapshot.
	// Versions start at 1 and increase by one for every commit that
	// effectively changes the configuration.
	Version uint64
	// Changes lists every key change of the commit, ordered by path.
	Changes []KeyChange
	// Matched lists the changed paths that fall inside the subscriber's
	// subscription scope, ordered by path. It is always a subset of Changes.
	Matched []string
}

// subscription binds a normalized path to a callback.
type subscription struct {
	id   uint64
	path string
	cb   func(ChangeEvent)
}

// Notifier implements snapshot-based change notification on top of a Viper
// instance. Callers subscribe to exact key paths or subtree paths; every
// explicit Commit compares the current effective configuration (per Viper's
// value precedence rules) against the previously published snapshot and
// notifies only the subscribers whose scope contains an added, removed or
// updated key.
//
// A Notifier is safe for concurrent use. Readers always observe either the
// complete old or the complete new published state, never a mixture.
type Notifier struct {
	v *Viper

	mu       sync.RWMutex
	version  uint64
	snapshot map[string]any
	changes  []KeyChange
	subs     map[uint64]subscription
	order    []uint64
	nextID   uint64
}

// NewNotifier creates a Notifier bound to v. The current effective
// configuration of v is captured as the initial (version 0) snapshot, so only
// changes committed after creation produce notifications.
func NewNotifier(v *Viper) *Notifier {
	return &Notifier{
		v:        v,
		snapshot: snapshotSettings(v),
		subs:     make(map[uint64]subscription),
	}
}

// Subscribe registers cb for changes under the given key path. The path may
// name an exact key (e.g. "log.level") or a subtree (e.g. "db"); it is
// normalized using Viper's case-insensitive key rules. The callback is
// invoked with a ChangeEvent whenever a commit changes at least one key
// inside the subscription scope.
//
// The returned function removes the subscription and is idempotent.
// Subscriptions added or removed from inside a callback only take effect for
// subsequent commits: the subscriber set of a commit is fixed when the
// commit starts.
func (n *Notifier) Subscribe(path string, cb func(ChangeEvent)) (unsubscribe func()) {
	n.mu.Lock()
	n.nextID++
	id := n.nextID
	n.subs[id] = subscription{id: id, path: normalizePath(path), cb: cb}
	n.order = append(n.order, id)
	n.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			n.mu.Lock()
			defer n.mu.Unlock()
			if _, ok := n.subs[id]; !ok {
				return
			}
			delete(n.subs, id)
			for i, oid := range n.order {
				if oid == id {
					n.order = append(n.order[:i], n.order[i+1:]...)
					break
				}
			}
		})
	}
}

// Commit captures the current effective configuration of the underlying
// Viper instance, compares it against the previously published snapshot and,
// if anything changed, atomically publishes the new snapshot with an
// incremented version and notifies the matching subscribers.
//
// It returns the published version and the ordered list of changes. When the
// commit introduces no effective change (for example when only the source of
// a value changed but the value itself did not), the version is left
// untouched, no subscriber is notified and an empty change list is returned.
//
// Callbacks run outside the publish lock, in subscription order. A panicking
// callback neither rolls back the published snapshot nor prevents the
// remaining subscribers from being notified.
func (n *Notifier) Commit() (uint64, []KeyChange) {
	// Fix the subscriber set for this commit before doing anything else, so
	// subscriptions changed from inside callbacks only affect later commits.
	n.mu.RLock()
	subs := make([]subscription, 0, len(n.order))
	for _, id := range n.order {
		if sub, ok := n.subs[id]; ok {
			subs = append(subs, sub)
		}
	}
	n.mu.RUnlock()

	candidate := snapshotSettings(n.v)

	n.mu.Lock()
	changes := diffSnapshots(n.snapshot, candidate)
	if len(changes) == 0 {
		version := n.version
		n.mu.Unlock()
		return version, nil
	}
	n.version++
	version := n.version
	n.snapshot = candidate
	n.changes = changes
	n.mu.Unlock()

	// Notify outside the publish lock.
	for _, sub := range subs {
		matched := matchedPaths(sub.path, changes)
		if len(matched) == 0 {
			continue
		}
		event := ChangeEvent{Version: version, Changes: changes, Matched: matched}
		notifySafely(sub.cb, event)
	}

	return version, changes
}

// Version returns the version of the currently published snapshot.
func (n *Notifier) Version() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.version
}

// LastCommit returns the version and the ordered change list of the most
// recent effective commit. The change list is nil when no effective commit
// has happened yet.
func (n *Notifier) LastCommit() (uint64, []KeyChange) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.version, append([]KeyChange(nil), n.changes...)
}

// Snapshot returns the version and a copy of the currently published
// configuration snapshot. The returned pair is always consistent: readers
// observe either the complete old or the complete new state, never a
// mixture of both.
func (n *Notifier) Snapshot() (uint64, map[string]any) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	cp := make(map[string]any, len(n.snapshot))
	for k, val := range n.snapshot {
		cp[k] = val
	}
	return n.version, cp
}

// snapshotSettings flattens the effective settings of v into a
// normalized-path -> value map. Unlike AllSettings it preserves nil values,
// so nil, empty lists and missing keys stay distinguishable.
func snapshotSettings(v *Viper) map[string]any {
	keys := v.AllKeys()
	m := make(map[string]any, len(keys))
	for _, k := range keys {
		m[normalizePath(k)] = v.Get(k)
	}
	return m
}

// normalizePath lowercases a delimiter-separated key path, following
// Viper's case-insensitive key handling.
func normalizePath(path string) string {
	return strings.ToLower(path)
}

// diffSnapshots computes the ordered list of changes that turns old into
// cur. Missing, nil and empty-list values are treated as distinct states.
func diffSnapshots(old, cur map[string]any) []KeyChange {
	var changes []KeyChange
	for path, curVal := range cur {
		oldVal, existed := old[path]
		switch {
		case !existed:
			changes = append(changes, KeyChange{Path: path, Kind: ChangeAdded})
		case !valuesEqual(oldVal, curVal):
			changes = append(changes, KeyChange{Path: path, Kind: ChangeUpdated})
		}
	}
	for path := range old {
		if _, ok := cur[path]; !ok {
			changes = append(changes, KeyChange{Path: path, Kind: ChangeRemoved})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

// valuesEqual reports whether two effective values are identical. Untyped
// nil, typed nil slices and empty slices are all considered different from
// each other; slice order is significant.
func valuesEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(a, b)
}

// pathInScope reports whether the changed path lies inside the scope of the
// subscription path: exact match, change below the subscribed subtree, or
// subscription below a removed or updated ancestor.
func pathInScope(subPath, changePath string) bool {
	return subPath == changePath ||
		strings.HasPrefix(changePath, subPath+".") ||
		strings.HasPrefix(subPath, changePath+".")
}

// matchedPaths returns the ordered changed paths falling inside the
// subscription scope.
func matchedPaths(subPath string, changes []KeyChange) []string {
	var matched []string
	for _, c := range changes {
		if pathInScope(subPath, c.Path) {
			matched = append(matched, c.Path)
		}
	}
	return matched
}

// notifySafely invokes a subscriber callback, isolating panics so a failing
// subscriber neither rolls back the published snapshot nor blocks the
// remaining subscribers.
func notifySafely(cb func(ChangeEvent), event ChangeEvent) {
	defer func() {
		// A panicking callback must not affect the commit or other subscribers.
		_ = recover()
	}()
	cb(event)
}
