package viper

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotifierSubtreeAndExactKey(t *testing.T) {
	v := New()
	v.Set("db.host", "localhost")
	v.Set("db.port", 5432)
	v.Set("log.level", "info")

	n := NewNotifier(v)

	var dbEvents, logEvents []ChangeEvent
	n.Subscribe("db", func(e ChangeEvent) { dbEvents = append(dbEvents, e) })
	n.Subscribe("log.level", func(e ChangeEvent) { logEvents = append(logEvents, e) })

	// Changing db.port must only notify the db subtree subscriber.
	v.Set("db.port", 5433)
	version, changes := n.Commit()

	require.Equal(t, uint64(1), version)
	require.Equal(t, []KeyChange{{Path: "db.port", Kind: ChangeUpdated}}, changes)
	require.Len(t, dbEvents, 1)
	assert.Empty(t, logEvents)
	assert.Equal(t, uint64(1), dbEvents[0].Version)
	assert.Equal(t, []string{"db.port"}, dbEvents[0].Matched)
	assert.Equal(t, changes, dbEvents[0].Changes)

	// The notification scope must be queryable after the commit.
	lastVersion, lastChanges := n.LastCommit()
	assert.Equal(t, uint64(1), lastVersion)
	assert.Equal(t, []KeyChange{{Path: "db.port", Kind: ChangeUpdated}}, lastChanges)

	// Changing log.level must only notify the exact-key subscriber.
	v.Set("log.level", "debug")
	version, changes = n.Commit()

	require.Equal(t, uint64(2), version)
	require.Equal(t, []KeyChange{{Path: "log.level", Kind: ChangeUpdated}}, changes)
	require.Len(t, logEvents, 1)
	assert.Len(t, dbEvents, 1)
	assert.Equal(t, uint64(2), logEvents[0].Version)
}

func TestNotifierDeleteKey(t *testing.T) {
	v := New()
	require.NoError(t, v.MergeConfigMap(map[string]any{
		"db":  map[string]any{"host": "localhost", "port": 5432},
		"top": "x",
	}))

	n := NewNotifier(v)

	var dbEvents, portEvents, hostEvents, topEvents []ChangeEvent
	n.Subscribe("db", func(e ChangeEvent) { dbEvents = append(dbEvents, e) })
	n.Subscribe("db.port", func(e ChangeEvent) { portEvents = append(portEvents, e) })
	n.Subscribe("db.host", func(e ChangeEvent) { hostEvents = append(hostEvents, e) })
	n.Subscribe("top", func(e ChangeEvent) { topEvents = append(topEvents, e) })

	// Delete a single key.
	delete(v.config["db"].(map[string]any), "port")
	version, changes := n.Commit()

	require.Equal(t, uint64(1), version)
	require.Equal(t, []KeyChange{{Path: "db.port", Kind: ChangeRemoved}}, changes)
	assert.Len(t, dbEvents, 1)
	assert.Len(t, portEvents, 1)
	assert.Empty(t, hostEvents)
	assert.Empty(t, topEvents)

	// Delete the whole subtree: the db.host subscriber is notified because
	// its key disappeared with the ancestor.
	delete(v.config, "db")
	version, changes = n.Commit()

	require.Equal(t, uint64(2), version)
	require.Equal(t, []KeyChange{{Path: "db.host", Kind: ChangeRemoved}}, changes)
	assert.Len(t, dbEvents, 2)
	assert.Len(t, hostEvents, 1)
	assert.Empty(t, topEvents)
}

func TestNotifierCaseInsensitiveAlias(t *testing.T) {
	v := New()
	v.RegisterAlias("LogLevel", "log.level")
	v.Set("log.level", "info")

	n := NewNotifier(v)

	var aliasEvents, realEvents []ChangeEvent
	n.Subscribe("LOGLEVEL", func(e ChangeEvent) { aliasEvents = append(aliasEvents, e) })
	n.Subscribe("Log.Level", func(e ChangeEvent) { realEvents = append(realEvents, e) })

	// Write through the mixed-case alias.
	v.Set("LOGLEVEL", "debug")
	version, changes := n.Commit()

	require.Equal(t, uint64(1), version)
	require.Equal(t, []KeyChange{
		{Path: "log.level", Kind: ChangeUpdated},
		{Path: "loglevel", Kind: ChangeUpdated},
	}, changes)
	assert.Len(t, aliasEvents, 1)
	assert.Len(t, realEvents, 1)

	// Write through the real key: the alias subscriber is still notified.
	v.Set("log.level", "warn")
	_, changes = n.Commit()

	require.Len(t, changes, 2)
	assert.Len(t, aliasEvents, 2)
	assert.Len(t, realEvents, 2)
}

func TestNotifierSourceOnlyChange(t *testing.T) {
	v := New()
	v.SetDefault("key", "value")

	n := NewNotifier(v)

	calls := 0
	n.Subscribe("key", func(ChangeEvent) { calls++ })

	// Committing an unchanged configuration is a no-op.
	version, changes := n.Commit()
	assert.Equal(t, uint64(0), version)
	assert.Empty(t, changes)
	assert.Zero(t, calls)

	// Same value from a different source (override instead of default):
	// no notification, no version bump.
	v.Set("key", "value")
	version, changes = n.Commit()
	assert.Equal(t, uint64(0), version)
	assert.Empty(t, changes)
	assert.Zero(t, calls)

	// Actually changing the value notifies and bumps the version.
	v.Set("key", "other")
	version, changes = n.Commit()
	assert.Equal(t, uint64(1), version)
	assert.Equal(t, []KeyChange{{Path: "key", Kind: ChangeUpdated}}, changes)
	assert.Equal(t, 1, calls)
}

func TestNotifierUnsubscribeInCallback(t *testing.T) {
	v := New()
	v.Set("k", 1)

	n := NewNotifier(v)

	var aCalls, bCalls int
	var unsubB func()
	n.Subscribe("k", func(ChangeEvent) {
		aCalls++
		unsubB()
	})
	unsubB = n.Subscribe("k", func(ChangeEvent) { bCalls++ })

	// The subscriber set is fixed when the commit starts: B is still
	// notified even though A's callback removes B first.
	v.Set("k", 2)
	n.Commit()
	assert.Equal(t, 1, aCalls)
	assert.Equal(t, 1, bCalls)

	// The removal takes effect for the next commit.
	v.Set("k", 3)
	n.Commit()
	assert.Equal(t, 2, aCalls)
	assert.Equal(t, 1, bCalls)

	// Unsubscribe is idempotent.
	unsubB()
}

func TestNotifierSubscribeInCallback(t *testing.T) {
	v := New()
	v.Set("k", 1)

	n := NewNotifier(v)

	var lateCalls int
	added := false
	n.Subscribe("k", func(ChangeEvent) {
		if !added {
			added = true
			n.Subscribe("k", func(ChangeEvent) { lateCalls++ })
		}
	})

	// A subscription added from inside a callback only affects later commits.
	v.Set("k", 2)
	n.Commit()
	assert.Zero(t, lateCalls)

	v.Set("k", 3)
	n.Commit()
	assert.Equal(t, 1, lateCalls)
}

func TestNotifierCallbackPanic(t *testing.T) {
	v := New()
	v.Set("k", 1)

	n := NewNotifier(v)

	goodCalls := 0
	n.Subscribe("k", func(ChangeEvent) { panic("boom") })
	n.Subscribe("k", func(ChangeEvent) { goodCalls++ })

	v.Set("k", 2)

	// The panicking callback neither aborts the commit nor blocks the
	// remaining subscribers.
	version, changes := n.Commit()
	assert.Equal(t, uint64(1), version)
	assert.Equal(t, []KeyChange{{Path: "k", Kind: ChangeUpdated}}, changes)
	assert.Equal(t, 1, goodCalls)

	// The new snapshot is published despite the panic.
	snapVersion, snap := n.Snapshot()
	assert.Equal(t, uint64(1), snapVersion)
	assert.Equal(t, 2, snap["k"])
}

func TestNotifierNilEmptyMissing(t *testing.T) {
	v := New()

	n := NewNotifier(v)

	var events []ChangeEvent
	n.Subscribe("item", func(e ChangeEvent) { events = append(events, e) })

	// missing -> nil: added
	v.Set("item", nil)
	_, changes := n.Commit()
	require.Equal(t, []KeyChange{{Path: "item", Kind: ChangeAdded}}, changes)

	// nil -> empty list: updated (nil and empty list are distinct)
	v.Set("item", []string{})
	_, changes = n.Commit()
	require.Equal(t, []KeyChange{{Path: "item", Kind: ChangeUpdated}}, changes)

	// empty list -> nil: updated
	v.Set("item", nil)
	_, changes = n.Commit()
	require.Equal(t, []KeyChange{{Path: "item", Kind: ChangeUpdated}}, changes)

	// nil -> missing: removed
	delete(v.override, "item")
	_, changes = n.Commit()
	require.Equal(t, []KeyChange{{Path: "item", Kind: ChangeRemoved}}, changes)

	// missing -> missing: no change
	version, changes := n.Commit()
	assert.Equal(t, uint64(4), version)
	assert.Empty(t, changes)

	assert.Len(t, events, 4)
}

func TestNotifierListOrderMatters(t *testing.T) {
	v := New()
	v.Set("list", []string{"a", "b"})

	n := NewNotifier(v)

	calls := 0
	n.Subscribe("list", func(ChangeEvent) { calls++ })

	// Reordering the list is a change.
	v.Set("list", []string{"b", "a"})
	version, changes := n.Commit()
	assert.Equal(t, uint64(1), version)
	assert.Equal(t, []KeyChange{{Path: "list", Kind: ChangeUpdated}}, changes)
	assert.Equal(t, 1, calls)

	// Committing the identical list is a no-op.
	v.Set("list", []string{"b", "a"})
	version, changes = n.Commit()
	assert.Equal(t, uint64(1), version)
	assert.Empty(t, changes)
	assert.Equal(t, 1, calls)
}

func TestNotifierVersionIncrementsAndStableOrder(t *testing.T) {
	v := New()
	v.Set("a", 1)
	v.Set("b", 2)
	v.Set("c", 3)

	n := NewNotifier(v)

	var versions []uint64
	n.Subscribe("a", func(e ChangeEvent) { versions = append(versions, e.Version) })

	for i := 1; i <= 3; i++ {
		v.Set("a", i+1)
		version, _ := n.Commit()
		assert.Equal(t, uint64(i), version)
	}
	assert.Equal(t, []uint64{1, 2, 3}, versions)

	// Changes of a single commit are reported in stable (sorted) order.
	v.Set("c", 4)
	v.Set("b", 5)
	v.Set("a", 6)
	_, changes := n.Commit()
	require.Len(t, changes, 3)
	assert.Equal(t, []KeyChange{
		{Path: "a", Kind: ChangeUpdated},
		{Path: "b", Kind: ChangeUpdated},
		{Path: "c", Kind: ChangeUpdated},
	}, changes)
}

func TestNotifierConcurrentReadersBarrier(t *testing.T) {
	v := New()
	v.Set("counter", 0)

	n := NewNotifier(v)

	const (
		readers = 8
		commits = 50
	)

	var barrier sync.WaitGroup
	barrier.Add(readers + 1)

	var done sync.WaitGroup
	done.Add(readers)

	errs := make(chan error, readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer done.Done()
			barrier.Done()
			barrier.Wait()

			var last uint64
			for {
				version, snap := n.Snapshot()
				commitVersion, changes := n.LastCommit()

				if version < last {
					errs <- fmt.Errorf("version went backwards: %d < %d", version, last)
					return
				}
				last = version

				// The (version, snapshot) pair must be consistent: readers
				// always see the complete old or the complete new state.
				if version == 0 && snap["counter"] != 0 {
					errs <- fmt.Errorf("version 0 with unexpected counter: %v", snap["counter"])
					return
				}
				if version > 0 && snap["counter"] != int(version) {
					errs <- fmt.Errorf("inconsistent snapshot: version %d with counter %v", version, snap["counter"])
					return
				}

				// The (version, changes) pair must be consistent as well.
				if commitVersion == 0 && changes != nil {
					errs <- fmt.Errorf("version 0 with changes: %v", changes)
					return
				}
				if commitVersion > 0 && len(changes) == 0 {
					errs <- fmt.Errorf("version %d without changes", commitVersion)
					return
				}

				if commitVersion >= commits {
					return
				}
			}
		}()
	}

	barrier.Done()
	barrier.Wait()

	for i := 1; i <= commits; i++ {
		v.Set("counter", i)
		n.Commit()
	}

	done.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	assert.Equal(t, uint64(commits), n.Version())
}

func ExampleNewNotifier() {
	v := New()
	v.Set("db.host", "localhost")
	v.Set("db.port", 5432)
	v.Set("log.level", "info")

	n := NewNotifier(v)
	unsubscribe := n.Subscribe("db", func(e ChangeEvent) {
		fmt.Printf("version=%d changed=%v\n", e.Version, e.Matched)
	})
	defer unsubscribe()

	// Apply candidate changes, then commit explicitly.
	v.Set("db.port", 5433)
	n.Commit()

	// Only the log.level subscriber scope changed here, so the db
	// subscriber stays silent.
	v.Set("log.level", "debug")
	n.Commit()

	// Output:
	// version=1 changed=[db.port]
}
