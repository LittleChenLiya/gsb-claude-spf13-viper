package viper

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNotifierPanicWithoutErrorHandlerIsRecovered ensures panics are isolated
// even when no error handler was supplied.
func TestNotifierPanicWithoutErrorHandlerIsRecovered(t *testing.T) {
	v := New()
	n := NewNotifier(v, nil)
	n.Commit()

	reached := make(chan struct{}, 1)
	s1 := n.Subscribe("a", func(Change) { panic("boom without handler") })
	s2 := n.Subscribe("a", func(Change) { reached <- struct{}{} })
	t.Cleanup(s1.Unsubscribe)
	t.Cleanup(s2.Unsubscribe)

	v.Set("a", 1)
	n.Commit() // must not panic into the caller

	select {
	case <-reached:
	default:
		t.Fatal("later subscriber was not notified after earlier panic")
	}
}

// TestNotifierCallbacksRunOutsideLock ensures callbacks may use any Notifier
// method (including Commit) without deadlocking.
func TestNotifierCallbacksRunOutsideLock(t *testing.T) {
	v := New()
	n := NewNotifier(v, nil)
	n.Commit()

	done := make(chan struct{})
	var sub *Subscription
	sub = n.Subscribe("a", func(c Change) {
		sub.Unsubscribe()
		n.CurrentVersion()
		_, _ = n.Snapshot()
		extra := n.Subscribe("a", func(Change) {})
		t.Cleanup(extra.Unsubscribe)
		if c.Version == 2 {
			v.Set("a", 2)
			n.Commit() // nested commit must not deadlock
		}
		close(done)
	})
	t.Cleanup(sub.Unsubscribe)

	v.Set("a", 1)
	n.Commit()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback deadlocked while calling notifier methods")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestNotifierNilEmptyListAndMissingDistinguished ensures nil values, empty
// lists and missing keys never collapse into one another.
func TestNotifierNilEmptyListAndMissingDistinguished(t *testing.T) {
	v := New()
	n := NewNotifier(v, nil)
	n.Commit()

	var changes []Change
	sub := n.SubscribeSubtree("", func(c Change) {
		changes = append(changes, Change{Version: c.Version, ChangedPaths: append([]string(nil), c.ChangedPaths...)})
	})
	t.Cleanup(sub.Unsubscribe)

	v.Set("nil.value", nil)
	n.Commit()
	if want := []string{"nil.value"}; !equalStrings(changes[0].ChangedPaths, want) {
		t.Fatalf("nil add: %v want %v", changes[0].ChangedPaths, want)
	}
	version, values := n.Snapshot()
	if version != changes[0].Version {
		t.Fatalf("snapshot version %d, change version %d", version, changes[0].Version)
	}
	if val, ok := values["nil.value"]; !ok || val != nil {
		t.Fatalf("nil.value present=%v val=%#v, want present nil", ok, val)
	}
	if _, ok := values["missing"]; ok {
		t.Fatal("missing key must not appear in snapshot")
	}

	// An explicitly empty list is its own value.
	v.Set("list", []string{})
	n.Commit()
	if want := []string{"list"}; !equalStrings(changes[1].ChangedPaths, want) {
		t.Fatalf("empty list add: %v want %v", changes[1].ChangedPaths, want)
	}
	if sl, ok := v.Get("list").([]string); !ok || len(sl) != 0 || sl == nil {
		t.Fatalf("list = %#v, want non-nil empty []string", v.Get("list"))
	}

	// Moving the nil value to the default layer must not notify.
	v.SetDefault("nil.value", nil)
	n.Commit()
	if len(changes) != 2 {
		t.Fatalf("source-only change notified: %d changes, want 2", len(changes))
	}

	// List order is significant.
	v.Set("list", []string{"x", "y"})
	n.Commit()
	v.Set("list", []string{"y", "x"})
	n.Commit()
	if len(changes) != 4 {
		t.Fatalf("got %d changes, want 4 (reordering must notify)", len(changes))
	}
	if want := []string{"list"}; !equalStrings(changes[3].ChangedPaths, want) {
		t.Fatalf("reorder paths %v, want %v", changes[3].ChangedPaths, want)
	}
}

// TestNotifierCallbackUnsubscribeOnlyAffectsFutureCommits freezes the
// subscriber set for one Commit: unsubscribing in a callback does not change
// delivery within the same Commit but affects later ones.
func TestNotifierCallbackUnsubscribeOnlyAffectsFutureCommits(t *testing.T) {
	v := New()
	n := NewNotifier(v, nil)
	n.Commit()

	var mu sync.Mutex
	first := make([]string, 0, 2)
	var selfSub, otherSub *Subscription
	selfSub = n.Subscribe("a", func(Change) {
		mu.Lock()
		first = append(first, "self")
		mu.Unlock()
		selfSub.Unsubscribe()
	})
	otherSub = n.Subscribe("a", func(Change) {
		mu.Lock()
		first = append(first, "other")
		mu.Unlock()
		otherSub.Unsubscribe()
	})

	v.Set("a", 1)
	n.Commit()
	mu.Lock()
	gotFirst := append([]string(nil), first...)
	mu.Unlock()
	if want := []string{"self", "other"}; !equalStrings(gotFirst, want) {
		t.Fatalf("first commit subscribers %v, want %v", gotFirst, want)
	}

	v.Set("a", 2)
	n.Commit()
	mu.Lock()
	gotFirst = append([]string(nil), first...)
	mu.Unlock()
	if want := []string{"self", "other"}; !equalStrings(gotFirst, want) {
		t.Fatalf("unsubscribe must affect later commits only, got %v", gotFirst)
	}

	// Subscribers added during delivery only participate from the next Commit.
	lateCalls := atomic.Int32{}
	var lateSub *Subscription
	adder := n.Subscribe("a", func(Change) {
		lateSub = n.Subscribe("b", func(Change) { lateCalls.Add(1) })
	})
	t.Cleanup(adder.Unsubscribe)

	v.Set("a", 3)
	n.Commit()
	if lateCalls.Load() != 0 {
		t.Fatalf("subscriber added in callback ran in same commit: %d", lateCalls.Load())
	}
	v.Set("b", 1)
	n.Commit()
	if lateCalls.Load() != 1 {
		t.Fatalf("late subscriber calls = %d, want 1", lateCalls.Load())
	}
	if lateSub != nil {
		t.Cleanup(lateSub.Unsubscribe)
	}
}

// TestNotifierCallbackErrorDoesNotBlockOthers ensures a panicking callback
// neither rolls back the published version nor stops later subscribers, and
// versions strictly increase in commit order.
func TestNotifierCallbackErrorDoesNotBlockOthers(t *testing.T) {
	v := New()
	v.SetDefault("k", "seed")
	seed := NewNotifier(v, nil)
	seed.Commit()

	var gotErr error
	n := NewNotifier(v, func(_ *Subscription, err error) { gotErr = err })
	n.snapshot = seed.snapshot
	n.version = seed.version

	var mu sync.Mutex
	order := make([]int, 0, 4)
	s1 := n.Subscribe("k", func(Change) {
		mu.Lock()
		order = append(order, 1)
		mu.Unlock()
		panic("boom")
	})
	s2 := n.Subscribe("k", func(Change) {
		mu.Lock()
		order = append(order, 2)
		mu.Unlock()
	})
	t.Cleanup(s1.Unsubscribe)
	t.Cleanup(s2.Unsubscribe)

	v.Set("k", "v1")
	n.Commit()
	if gotErr == nil {
		t.Fatal("error handler not invoked for panicking callback")
	}
	mu.Lock()
	gotOrder := append([]int(nil), order...)
	mu.Unlock()
	if want := []int{1, 2}; len(gotOrder) != 2 || gotOrder[0] != want[0] || gotOrder[1] != want[1] {
		t.Fatalf("callback order %v, want %v (panic must not block later callback)", gotOrder, want)
	}
	if n.CurrentVersion() != 2 {
		t.Fatalf("version after panic = %d, want 2 (commit must not roll back)", n.CurrentVersion())
	}

	v.Set("k", "v2")
	n.Commit()
	if n.CurrentVersion() != 3 {
		t.Fatalf("version = %d, want monotonic 3", n.CurrentVersion())
	}
}

// TestNotifierReadBarrier runs readers concurrently with commits and asserts
// every reader observes a complete, internally consistent version: either the
// full old snapshot or the full new snapshot, never a torn mixture.
func TestNotifierReadBarrier(t *testing.T) {
	v := New()
	const keys = 64
	for i := 0; i < keys; i++ {
		v.SetDefault(fmt.Sprintf("k%02d", i), "v0")
	}
	n := NewNotifier(v, nil)
	n.Commit()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var violations atomic.Int64

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				version, snap := n.Snapshot()
				if len(snap) != keys {
					violations.Add(1)
					return
				}
				want := fmt.Sprintf("v%d", version-1)
				for i := 0; i < keys; i++ {
					if snap[fmt.Sprintf("k%02d", i)] != want {
						violations.Add(1)
						return
					}
				}
			}
		}()
	}

	for version := 2; version <= 20; version++ {
		want := fmt.Sprintf("v%d", version-1)
		for i := 0; i < keys; i++ {
			v.Set(fmt.Sprintf("k%02d", i), want)
		}
		n.Commit()
		if n.CurrentVersion() != uint64(version) {
			t.Fatalf("version = %d, want %d", n.CurrentVersion(), version)
		}
	}
	close(stop)
	wg.Wait()

	if violations.Load() != 0 {
		t.Fatalf("observed %d torn/inconsistent snapshots", violations.Load())
	}
}

// TestNotifierAliasNormalization subscribes through a mixed-case alias and
// checks that Viper normalization makes alias and canonical path equal.
func TestNotifierAliasNormalization(t *testing.T) {
	v := New()
	v.SetDefault("database.port", 5432)
	v.RegisterAlias("DB.Port", "database.port")
	n := NewNotifier(v, nil)
	n.Commit()

	if got, want := n.normalizePath("DB.PORT"), "database.port"; got != want {
		t.Fatalf("normalized alias %q, want %q", got, want)
	}

	var viaAlias, viaCanonical []Change
	subAlias := n.Subscribe("db.port", func(c Change) { viaAlias = append(viaAlias, c) })
	subCanonical := n.Subscribe("DaTaBaSe.PoRt", func(c Change) { viaCanonical = append(viaCanonical, c) })
	t.Cleanup(subAlias.Unsubscribe)
	t.Cleanup(subCanonical.Unsubscribe)

	v.Set("database.port", 6543)
	n.Commit()

	if len(viaAlias) != 1 || len(viaCanonical) != 1 {
		t.Fatalf("alias=%d canonical=%d notifications, want 1 each", len(viaAlias), len(viaCanonical))
	}
	// AllKeys exposes both the alias path and the canonical path, so both
	// appear in the sorted change set.
	if want := []string{"database.port", "db.port"}; !equalStrings(viaAlias[0].ChangedPaths, want) {
		t.Fatalf("changed paths %v, want %v", viaAlias[0].ChangedPaths, want)
	}
}

// TestNotifierSourceChangeOnly verifies moving a value between Viper layers
// without changing the effective value produces no notification or version.
func TestNotifierSourceChangeOnly(t *testing.T) {
	v := New()
	v.SetDefault("k", "same")
	n := NewNotifier(v, nil)
	n.Commit()

	notified := make(chan Change, 1)
	sub := n.Subscribe("k", func(c Change) { notified <- c })
	t.Cleanup(sub.Unsubscribe)

	v.Set("k", "same") // override layer, identical effective value
	n.Commit()

	select {
	case c := <-notified:
		t.Fatalf("source-only change delivered %+v", c)
	default:
	}
	if n.CurrentVersion() != 1 {
		t.Fatalf("version = %d after source-only commit, want 1", n.CurrentVersion())
	}
}

// TestNotifierSubtreeAndExactPath verifies the headline acceptance case:
// subscribing to the db subtree and to log.level, changing db.port only
// notifies the subtree subscription, and ChangedPaths exposes the scope.
func TestNotifierSubtreeAndExactPath(t *testing.T) {
	v := New()
	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5432)
	v.SetDefault("log.level", "info")
	n := NewNotifier(v, nil)
	n.Commit() // publish baseline

	var dbPaths, logPaths []string
	dbSub := n.SubscribeSubtree("db", func(c Change) {
		dbPaths = append(dbPaths, c.ChangedPaths...)
	})
	logSub := n.Subscribe("log.level", func(c Change) {
		logPaths = append(logPaths, c.ChangedPaths...)
	})
	t.Cleanup(dbSub.Unsubscribe)
	t.Cleanup(logSub.Unsubscribe)

	v.Set("db.port", 6543)
	n.Commit()

	if want := []string{"db.port"}; !equalStrings(dbPaths, want) {
		t.Fatalf("db subtree notified with %v, want %v", dbPaths, want)
	}
	if len(logPaths) != 0 {
		t.Fatalf("log.level subscriber notified with %v, want nothing", logPaths)
	}

	v.Set("log.level", "debug")
	n.Commit()
	if want := []string{"log.level"}; !equalStrings(logPaths, want) {
		t.Fatalf("log.level subscriber notified with %v, want %v", logPaths, want)
	}
}

// TestNotifierAddChangeAndDelete covers added, changed and removed leaf keys.
func TestNotifierAddChangeAndDelete(t *testing.T) {
	v := New()
	v.SetDefault("a", 1)
	v.SetDefault("keep", "x")
	n := NewNotifier(v, nil)
	n.Commit()

	var got Change
	sub := n.SubscribeSubtree("", func(c Change) { got = c })
	t.Cleanup(sub.Unsubscribe)

	v.SetDefault("b", 2)
	v.Set("a", 10)
	n.Commit()

	if got.Version != 2 || got.PreviousVersion != 1 {
		t.Fatalf("got version %d <- %d, want 2 <- 1", got.Version, got.PreviousVersion)
	}
	if want := []string{"a", "b"}; !equalStrings(got.ChangedPaths, want) {
		t.Fatalf("changed paths %v, want %v", got.ChangedPaths, want)
	}

	// Rebuild state with b present, publish it, then remove b entirely.
	v.defaults = map[string]any{"a": 10, "keep": "x", "b": 1}
	v.override = map[string]any{}
	n.Commit()
	v.defaults = map[string]any{"a": 10, "keep": "x"}
	n.Commit()
	if want := []string{"b"}; !equalStrings(got.ChangedPaths, want) {
		t.Fatalf("removed paths %v, want %v", got.ChangedPaths, want)
	}
	if got.Version != 4 {
		t.Fatalf("version after delete = %d, want 4", got.Version)
	}
}
