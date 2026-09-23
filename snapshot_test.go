package viper

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func newSnapshotTestViper() *Viper {
	v := New()
	v.Set("host", "a")
	v.Set("port", 80)
	return v
}

func validatePositivePort(s *Snapshot) error {
	if s.GetInt("port") < 0 {
		return fmt.Errorf("port must not be negative: %d", s.GetInt("port"))
	}
	return nil
}

func TestSnapshotPublisherRejectedCandidateKeepsWholeOldSnapshot(t *testing.T) {
	v := newSnapshotTestViper()
	pub, err := NewSnapshotPublisher(v, validatePositivePort)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Close() })

	initial := pub.Load()
	require.Equal(t, uint64(1), initial.Version())
	require.Equal(t, "a", initial.GetString("host"))
	require.Equal(t, 80, initial.GetInt("port"))

	v.Set("host", "b")
	v.Set("port", -1)

	candidate, err := pub.Build(context.Background())
	require.NoError(t, err)

	// The candidate itself reflects the new values.
	require.Equal(t, "b", candidate.settings["host"])
	require.Equal(t, -1, candidate.settings["port"])

	_, err = candidate.Publish(context.Background())
	require.Error(t, err)

	// Repeated reads keep seeing the old version as a whole: both fields
	// together, no mixed new/old state, version unchanged.
	for range 3 {
		current := pub.Load()
		require.Equal(t, uint64(1), current.Version())
		require.Equal(t, "a", current.GetString("host"))
		require.Equal(t, 80, current.GetInt("port"))
	}

	v.Set("port", 81)
	candidate, err = pub.Build(context.Background())
	require.NoError(t, err)

	published, err := candidate.Publish(context.Background())
	require.NoError(t, err)

	// A successful publish changes both fields atomically and bumps the version.
	require.Equal(t, uint64(2), published.Version())
	current := pub.Load()
	require.Equal(t, uint64(2), current.Version())
	require.Equal(t, "b", current.GetString("host"))
	require.Equal(t, 81, current.GetInt("port"))

	// The old snapshot object is still the old, fully readable version.
	require.Equal(t, "a", initial.GetString("host"))
	require.Equal(t, 80, initial.GetInt("port"))

	// Get must honor Viper's key case-insensitivity.
	require.Equal(t, "b", current.GetString("HOST"))
}

func TestSnapshotPublisherStaleGenerationDoesNotOverwrite(t *testing.T) {
	v := newSnapshotTestViper()

	var mu sync.Mutex
	var hook func(*Snapshot) error
	validate := func(s *Snapshot) error {
		mu.Lock()
		h := hook
		mu.Unlock()
		if h != nil {
			return h(s)
		}
		return nil
	}

	pub, err := NewSnapshotPublisher(v, validate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Close() })

	v.Set("host", "b")
	candidate1, err := pub.Build(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(2), candidate1.Generation())

	v.Set("host", "c")
	candidate2, err := pub.Build(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(3), candidate2.Generation())

	entered := make(chan struct{})
	release := make(chan struct{})
	mu.Lock()
	hook = func(s *Snapshot) error {
		if s.GetString("host") == "b" {
			close(entered)
			<-release
		}
		return nil
	}
	mu.Unlock()

	publishErr := make(chan error, 1)
	go func() {
		_, e := candidate1.Publish(context.Background())
		publishErr <- e
	}()

	<-entered

	// The newer generation publishes while generation 2 is stuck in validation.
	published2, err := candidate2.Publish(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(2), published2.Version())

	close(release)
	require.ErrorIs(t, <-publishErr, ErrStaleSnapshotGeneration)

	current := pub.Load()
	require.Equal(t, uint64(2), current.Version())
	require.Equal(t, "c", current.GetString("host"))
	require.Equal(t, 80, current.GetInt("port"))
}

func TestSnapshotPublisherEnvSampledOnceAtBuild(t *testing.T) {
	v := New()
	v.SetDefault("host", "default")
	v.AutomaticEnv()

	t.Setenv("HOST", "env-a")

	pub, err := NewSnapshotPublisher(v, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Close() })
	require.Equal(t, "env-a", pub.Load().GetString("host"))

	candidate, err := pub.Build(context.Background())
	require.NoError(t, err)

	// Environment changes after Build starts must not reach the candidate
	// or the published snapshot.
	t.Setenv("HOST", "env-b")

	require.Equal(t, "env-a", candidate.settings["host"])

	published, err := candidate.Publish(context.Background())
	require.NoError(t, err)
	require.Equal(t, "env-a", published.GetString("host"))

	t.Setenv("HOST", "env-c")
	require.Equal(t, "env-a", pub.Load().GetString("host"))
}

func TestSnapshotPublisherNestedContainersAreIsolated(t *testing.T) {
	v := New()
	nested := map[string]any{
		"tags":  []any{"x", "y"},
		"inner": map[string]any{"name": "deep"},
	}
	v.Set("server", nested)

	pub, err := NewSnapshotPublisher(v, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Close() })

	// Mutating the container the caller handed to Set cannot reach the
	// published snapshot.
	nested["tags"].([]any)[0] = "mutated"
	nested["inner"].(map[string]any)["name"] = "mutated"

	current := pub.Load()
	tags := current.Get("server.tags").([]any)
	require.Equal(t, []any{"x", "y"}, tags)
	require.Equal(t, "deep", current.Get("server.inner.name"))

	// Mutating containers returned by Get cannot reach the snapshot either.
	tags[0] = "again"
	current.Get("server.tags").([]any)[0] = "again"
	current.Get("server.inner").(map[string]any)["name"] = "again"

	require.Equal(t, []any{"x", "y"}, pub.Load().Get("server.tags"))
	require.Equal(t, "deep", pub.Load().Get("server.inner.name"))

	// AllSettings returns an independent copy as well.
	all := pub.Load().AllSettings()
	all["server"].(map[string]any)["tags"].([]any)[1] = "mutated"
	require.Equal(t, []any{"x", "y"}, pub.Load().Get("server.tags"))
}

type snapshotTestConfig struct {
	Host string
	Port int
}

func TestSnapshotPublisherGetAndUnmarshalReadOnlySnapshot(t *testing.T) {
	v := New()
	v.Set("host", "a")
	v.Set("port", 80)

	pub, err := NewSnapshotPublisher(v, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Close() })

	v.Set("host", "changed")
	v.Set("port", 9090)

	snap := pub.Load()

	var cfg snapshotTestConfig
	require.NoError(t, snap.Unmarshal(&cfg))
	require.Equal(t, snapshotTestConfig{Host: "a", Port: 80}, cfg)
	require.Equal(t, "a", snap.GetString("host"))
}

func TestSnapshotPublisherConcurrentLoadsAndPublishes(t *testing.T) {
	v := newSnapshotTestViper()
	pub, err := NewSnapshotPublisher(v, validatePositivePort)
	require.NoError(t, err)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap := pub.Load()
				if snap.GetString("host") == "" {
					t.Errorf("empty host")
					return
				}
				if snap.GetInt("port") < 0 {
					t.Errorf("invalid published port: %d", snap.GetInt("port"))
					return
				}
				var cfg snapshotTestConfig
				if err := snap.Unmarshal(&cfg); err != nil {
					t.Errorf("unmarshal: %v", err)
					return
				}
				if cfg.Host != snap.GetString("host") || cfg.Port != snap.GetInt("port") {
					t.Errorf("mixed snapshot read: %+v", cfg)
					return
				}
			}
		}()
	}

	for i := range 50 {
		v.Set("host", fmt.Sprintf("host-%d", i))
		v.Set("port", 80+i)
		candidate, err := pub.Build(context.Background())
		require.NoError(t, err)
		_, err = candidate.Publish(context.Background())
		require.NoError(t, err)

		// Every failed publish leaves the version untouched.
		v.Set("port", -1)
		bad, err := pub.Build(context.Background())
		require.NoError(t, err)
		_, err = bad.Publish(context.Background())
		require.Error(t, err)
		v.Set("port", 80+i)
	}

	close(stop)
	wg.Wait()
	require.NoError(t, pub.Close())

	final := pub.Load()
	require.Equal(t, "host-49", final.GetString("host"))
	require.Equal(t, 129, final.GetInt("port"))
	require.Equal(t, uint64(51), final.Version())
}

func TestSnapshotPublisherContextCancelAndClose(t *testing.T) {
	v := newSnapshotTestViper()
	pub, err := NewSnapshotPublisher(v, validatePositivePort)
	require.NoError(t, err)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = pub.Build(canceledCtx)
	require.ErrorIs(t, err, context.Canceled)

	candidate, err := pub.Build(context.Background())
	require.NoError(t, err)
	_, err = candidate.Publish(canceledCtx)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, uint64(1), pub.Load().Version())

	// Canceling an unpublished candidate does not affect the current snapshot.
	require.Equal(t, "a", pub.Load().GetString("host"))

	require.NoError(t, pub.Close())

	_, err = pub.Build(context.Background())
	require.ErrorIs(t, err, ErrSnapshotPublisherClosed)
	_, err = candidate.Publish(context.Background())
	require.ErrorIs(t, err, ErrSnapshotPublisherClosed)

	// Load keeps working and already obtained snapshots stay readable.
	snap := pub.Load()
	require.Equal(t, uint64(1), snap.Version())
	require.Equal(t, "a", snap.GetString("host"))
	require.Equal(t, 80, snap.GetInt("port"))

	// Close is idempotent.
	require.NoError(t, pub.Close())
}

func TestSnapshotPublisherNilSource(t *testing.T) {
	_, err := NewSnapshotPublisher(nil, nil)
	require.Error(t, err)
}

func TestSnapshotPublisherInitialValidationFailure(t *testing.T) {
	v := New()
	v.Set("port", -1)

	_, err := NewSnapshotPublisher(v, validatePositivePort)
	require.Error(t, err)
}
