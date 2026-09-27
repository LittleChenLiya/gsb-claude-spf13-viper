package viper

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// nilValue is stored in snapshots for keys that resolve to an effective nil
// value. It keeps nil distinguishable from a key that is absent from the
// configuration (the latter simply does not appear in the snapshot map).
type nilValue struct{}

// Change describes a single committed configuration version.
//
// Version is monotonically increasing for each Commit call that changed at
// least one effective value. PreviousVersion is the version of the snapshot used
// for comparison (zero for the first committed version). ChangedPaths lists
// every leaf key that was added, removed or actually changed between the two
// snapshots, normalized per Viper rules (lower case, key delimiter separated).
//
// Change intentionally does not carry configuration values.
type Change struct {
	// Version of the snapshot that triggered this notification.
	Version uint64

	// PreviousVersion is the version this snapshot was compared against.
	// It is zero for the first Commit.
	PreviousVersion uint64

	// ChangedPaths lists added, removed and changed effective leaf keys.
	ChangedPaths []string
}

// ChangeFunc is invoked after a Commit when one of the paths a subscription
// watches has changed. Callbacks run outside the notifier lock, so they may
// call Unsubscribe (and other Notifier methods) safely.
type ChangeFunc func(change Change)

// ErrorFunc is invoked when a callback panics. A nil handler leaves panics
// recovered silently: a failing callback never rolls back a committed
// configuration and never prevents other callbacks from running.
type ErrorFunc func(subscription *Subscription, err error)

// Notifier compares full effective configuration snapshots.
//
// Subscriptions use Viper-normalized key paths: an exact path watches only
// that leaf, a subtree path watches the path itself and every descendant.
// Comparison uses the same effective value rules as Viper.Get: moving a value
// between sources (for example defaults, config file, overrides) without
// changing the effective value does not produce a notification.
//
// All reads see either the complete previous or the complete next snapshot;
// callers that need a consistent view can use Snapshot together with
// CurrentVersion as a read barrier.
type Notifier struct {
	v *Viper

	mu       sync.RWMutex
	subs     []*subscription
	nextID   uint64
	version  uint64
	snapshot map[string]any
	onError  ErrorFunc
}

type subscription struct {
	id       uint64
	path     string
	subtree  bool
	callback ChangeFunc
	deleted  bool
}

// NewNotifier creates a Notifier bound to the given Viper instance.
// onError may be nil; otherwise it is invoked (outside the lock) when a
// callback panics.
func NewNotifier(v *Viper, onError ErrorFunc) *Notifier {
	return &Notifier{
		v:       v,
		onError: onError,
	}
}

// Subscribe registers a callback for an exact key path. The path is
// normalized per Viper rules (lower case, delimiter separated, aliases
// resolved). It returns a Subscription used to cancel delivery.
func (n *Notifier) Subscribe(path string, callback ChangeFunc) *Subscription {
	return n.subscribe(path, false, callback)
}

// SubscribeSubtree registers a callback for a path and every descendant of
// it. Subscribing to the empty path watches the whole configuration.
func (n *Notifier) SubscribeSubtree(path string, callback ChangeFunc) *Subscription {
	return n.subscribe(path, true, callback)
}

func (n *Notifier) subscribe(path string, subtree bool, callback ChangeFunc) *Subscription {
	if callback == nil {
		panic("viper: change callback must not be nil")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.nextID++
	sub := &subscription{
		id:       n.nextID,
		path:     n.normalizePath(path),
		subtree:  subtree,
		callback: callback,
	}
	n.subs = append(n.subs, sub)
	return &Subscription{n: n, sub: sub}
}

func (n *Notifier) normalizePath(path string) string {
	delim := n.v.keyDelim
	if delim == "" {
		delim = "."
	}
	parts := strings.Split(path, delim)
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		normalized = append(normalized, part)
	}
	joined := strings.Join(normalized, delim)
	// Resolve aliases exactly like Viper.Get does, so subscriptions by alias
	// and by canonical key are equivalent.
	return n.v.realKey(joined)
}

// Commit captures the current effective configuration as a new snapshot,
// compares it against the previous one and notifies affected subscriptions.
//
// The set of subscribers for this Commit is fixed while the notifier lock is
// held; callbacks run afterwards without the lock. Subscriptions added or
// removed from a callback take effect starting with the next Commit. If no
// effective value changed no new version is published and nothing is
// notified.
func (n *Notifier) Commit() {
	nextSnapshot := n.captureSnapshot()

	n.mu.Lock()
	changed := diffSnapshots(n.snapshot, nextSnapshot)
	if len(changed) == 0 {
		n.mu.Unlock()
		return
	}

	previousVersion := n.version
	nextVersion := previousVersion + 1
	n.version = nextVersion
	n.snapshot = nextSnapshot

	change := Change{
		Version:         nextVersion,
		PreviousVersion: previousVersion,
		ChangedPaths:    changed,
	}
	delivery := make([]pendingDelivery, 0, len(n.subs))
	for _, sub := range n.subs {
		if sub.deleted {
			continue
		}
		if !sub.affected(change.ChangedPaths) {
			continue
		}
		delivery = append(delivery, pendingDelivery{sub: sub, change: change})
	}
	n.compactLocked()
	n.mu.Unlock()

	for _, d := range delivery {
		n.deliver(d)
	}
}

type pendingDelivery struct {
	sub    *subscription
	change Change
}

func (n *Notifier) deliver(d pendingDelivery) {
	defer func() {
		if r := recover(); r != nil && n.onError != nil {
			handle := &Subscription{n: n, sub: d.sub}
			n.onError(handle, fmt.Errorf("viper: change callback panicked: %v", r))
		}
	}()
	d.sub.callback(d.change)
}

func (n *Notifier) compactLocked() {
	kept := n.subs[:0]
	for _, sub := range n.subs {
		if !sub.deleted {
			kept = append(kept, sub)
		}
	}
	n.subs = kept
}

// captureSnapshot builds an immutable map of every effective leaf key using
// the same resolution rules as Viper.Get. AllKeys lists leaf keys from every
// layer (including aliases) and Get returns the effective value, so source
// changes without value changes are invisible here.
func (n *Notifier) captureSnapshot() map[string]any {
	keys := n.v.AllKeys()
	snapshot := make(map[string]any, len(keys))
	for _, key := range keys {
		value := n.v.Get(key)
		if value == nil {
			value = nilValue{}
		}
		snapshot[key] = value
	}
	return snapshot
}

// CurrentVersion returns the version of the snapshot currently published.
// It returns zero before the first Commit that published a change.
func (n *Notifier) CurrentVersion() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.version
}

// Snapshot returns a copy of the currently published effective configuration
// together with its version. Readers can pair the two values as a barrier:
// both describe the same complete version and never an in-between state. The
// returned map is safe to retain. Effective nil values map to nil; keys absent
// from the configuration are absent from the map.
func (n *Notifier) Snapshot() (uint64, map[string]any) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	out := make(map[string]any, len(n.snapshot))
	for key, value := range n.snapshot {
		if _, ok := value.(nilValue); ok {
			out[key] = nil
		} else {
			out[key] = value
		}
	}
	return n.version, out
}

// Subscription is a handle returned by Subscribe and SubscribeSubtree.
type Subscription struct {
	n   *Notifier
	sub *subscription
}

// Path returns the normalized watched path.
func (s *Subscription) Path() string {
	s.n.mu.RLock()
	defer s.n.mu.RUnlock()
	return s.sub.path
}

// Subtree reports whether the subscription covers descendants of Path.
func (s *Subscription) Subtree() bool {
	return s.sub.subtree
}

// Unsubscribe cancels the subscription. It only affects future Commits: when
// invoked from a callback of the Commit currently being delivered, the
// subscription still appears in the fixed subscriber set of that Commit.
func (s *Subscription) Unsubscribe() {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	s.sub.deleted = true
}

func (s *subscription) affected(changedPaths []string) bool {
	for _, changed := range changedPaths {
		if s.matches(changed) {
			return true
		}
	}
	return false
}

// matches reports whether a change at path should be delivered to this
// subscription. An exact subscription matches only the exact path; a subtree
// subscription matches the path itself and all of its descendants.
func (s *subscription) matches(path string) bool {
	if s.subtree {
		return s.path == "" || path == s.path || strings.HasPrefix(path, s.path+".")
	}
	return path == s.path
}

// diffSnapshots returns the sorted list of leaf keys added to next, removed
// from prev, or whose effective value changed. Slice comparison is ordered;
// nil values and missing keys are distinguished by map membership.
func diffSnapshots(prev, next map[string]any) []string {
	changedSet := make(map[string]struct{})
	for key, nextValue := range next {
		prevValue, ok := prev[key]
		switch {
		case !ok:
			changedSet[key] = struct{}{}
		case !equalValue(prevValue, nextValue):
			changedSet[key] = struct{}{}
		}
	}
	for key := range prev {
		if _, ok := next[key]; !ok {
			changedSet[key] = struct{}{}
		}
	}
	if len(changedSet) == 0 {
		return nil
	}
	changed := make([]string, 0, len(changedSet))
	for key := range changedSet {
		changed = append(changed, key)
	}
	sort.Strings(changed)
	return changed
}

// equalValue compares effective values the way Viper presents them. Slices
// compare element by element in order, including the distinction between a
// nil slice and a non-nil empty slice. nilValue markers compare by identity.
func equalValue(a, b any) bool {
	_, aNil := a.(nilValue)
	_, bNil := b.(nilValue)
	if aNil || bNil {
		return aNil == bNil
	}
	if aType, bType := reflect.TypeOf(a), reflect.TypeOf(b); aType != bType {
		return false
	}
	return reflect.DeepEqual(a, b)
}
