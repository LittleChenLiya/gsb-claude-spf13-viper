package viper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func portValidator(settings map[string]any) error {
	port, ok := settings["port"].(int)
	if !ok {
		return errors.New("port missing")
	}
	if port < 0 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

func TestPublisherValidationFailureKeepsOldSnapshot(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, portValidator)
	require.NoError(t, err)

	initial := p.Load()
	assert.Equal(t, "a", initial.GetString("host"))
	assert.Equal(t, 80, initial.GetInt("port"))
	assert.Equal(t, uint64(1), initial.Version())

	// Candidate with an invalid port is rejected as a whole.
	v.Set("host", "b")
	v.Set("port", -1)

	bad, err := p.Build(context.Background())
	require.NoError(t, err)
	_, err = bad.Publish(context.Background())
	require.Error(t, err)

	// Repeated reads still see the old snapshot, version unchanged.
	for range 3 {
		snap := p.Load()
		assert.Equal(t, "a", snap.GetString("host"))
		assert.Equal(t, 80, snap.GetInt("port"))
		assert.Equal(t, uint64(1), snap.Version())
		assert.Equal(t, uint64(1), p.Version())
	}

	// A valid candidate publishes both fields together.
	v.Set("port", 81)
	good, err := p.Build(context.Background())
	require.NoError(t, err)
	snap, err := good.Publish(context.Background())
	require.NoError(t, err)

	assert.Equal(t, uint64(2), snap.Version())
	assert.Equal(t, "b", snap.GetString("host"))
	assert.Equal(t, 81, snap.GetInt("port"))

	current := p.Load()
	assert.Equal(t, "b", current.GetString("host"))
	assert.Equal(t, 81, current.GetInt("port"))

	// The old snapshot remains fully readable.
	assert.Equal(t, "a", initial.GetString("host"))
	assert.Equal(t, 80, initial.GetInt("port"))
}

func TestPublisherStaleGenerationCannotOverwrite(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	entered := make(chan struct{})
	release := make(chan struct{})
	validate := func(settings map[string]any) error {
		if settings["host"] == "b1" {
			// Barrier: hold generation 1 inside validation until
			// generation 2 has been published.
			close(entered)
			<-release
		}
		return nil
	}

	p, err := NewPublisher(v, validate)
	require.NoError(t, err)

	v.Set("host", "b1")
	c1, err := p.Build(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(1), c1.Generation())

	v.Set("host", "b2")
	c2, err := p.Build(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(2), c2.Generation())

	var wg sync.WaitGroup
	var err1 error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = c1.Publish(context.Background())
	}()

	<-entered // generation 1 is now blocked inside validation

	snap2, err := c2.Publish(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(2), snap2.Version())
	assert.Equal(t, "b2", snap2.GetString("host"))

	close(release)
	wg.Wait()

	// The older generation finishes late and must not overwrite.
	require.ErrorIs(t, err1, ErrStaleGeneration)
	assert.Equal(t, uint64(2), p.Version())
	assert.Equal(t, "b2", p.Load().GetString("host"))
}

func TestPublisherEnvSampledOnceAtBuild(t *testing.T) {
	t.Setenv("SNAPSHOT_TEST_HOST", "env-a")

	v := New()
	v.SetEnvPrefix("snapshot_test")
	v.AutomaticEnv()
	v.SetDefault("host", "default")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, nil)
	require.NoError(t, err)
	assert.Equal(t, "env-a", p.Load().GetString("host"))

	t.Setenv("SNAPSHOT_TEST_HOST", "env-b")
	candidate, err := p.Build(context.Background())
	require.NoError(t, err)

	// Changing the environment after Build must not affect the candidate:
	// the variable was sampled once, at Build time.
	t.Setenv("SNAPSHOT_TEST_HOST", "env-c")

	snap, err := candidate.Publish(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "env-b", snap.GetString("host"))
	assert.Equal(t, "env-b", p.Load().GetString("host"))
}

func TestPublisherNestedContainersAreIsolated(t *testing.T) {
	v := New()
	v.SetDefault("server", map[string]any{
		"host":  "a",
		"ports": []any{80, 81},
	})

	p, err := NewPublisher(v, nil)
	require.NoError(t, err)
	snap := p.Load()

	// Mutating nested containers reachable through the source Viper must
	// not leak into the published snapshot.
	nested, ok := v.Get("server").(map[string]any)
	require.True(t, ok)
	nested["host"] = "mutated"
	ports, ok := nested["ports"].([]any)
	require.True(t, ok)
	ports[0] = -1

	assert.Equal(t, "a", snap.GetString("server.host"))
	assert.Equal(t, []any{80, 81}, snap.Get("server.ports"))

	// Mutating containers handed out by the snapshot itself must not
	// corrupt it either.
	handed, ok := snap.Get("server").(map[string]any)
	require.True(t, ok)
	handed["host"] = "mutated-again"
	assert.Equal(t, "a", snap.GetString("server.host"))
}

func TestPublisherConcurrentLoad(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, portValidator)
	require.NoError(t, err)

	type serverConfig struct {
		Host string
		Port int
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap := p.Load()
				var cfg serverConfig
				if err := snap.Unmarshal(&cfg); err != nil {
					t.Error(err)
					return
				}
				_ = snap.Get("host")
				_ = snap.AllSettings()
			}
		}()
	}

	for i := 1; i <= 20; i++ {
		v.Set("port", 80+i)
		candidate, err := p.Build(context.Background())
		require.NoError(t, err)
		_, err = candidate.Publish(context.Background())
		require.NoError(t, err)
	}

	close(stop)
	wg.Wait()

	assert.Equal(t, uint64(21), p.Version())
	assert.Equal(t, 100, p.Load().GetInt("port"))
}

func TestPublisherClose(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, nil)
	require.NoError(t, err)

	pending, err := p.Build(context.Background())
	require.NoError(t, err)

	old := p.Load()
	require.NoError(t, p.Close())

	_, err = p.Build(context.Background())
	require.ErrorIs(t, err, ErrPublisherClosed)

	_, err = pending.Publish(context.Background())
	require.ErrorIs(t, err, ErrPublisherClosed)

	// Snapshots obtained before Close stay readable.
	assert.Equal(t, "a", old.GetString("host"))
	assert.Equal(t, 80, old.GetInt("port"))
	assert.Equal(t, old, p.Load())
}

func TestPublisherContextCancellation(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = p.Build(ctx)
	require.ErrorIs(t, err, context.Canceled)

	candidate, err := p.Build(context.Background())
	require.NoError(t, err)

	_, err = candidate.Publish(ctx)
	require.ErrorIs(t, err, context.Canceled)

	// Cancelling an unpublished candidate does not touch the current
	// snapshot.
	assert.Equal(t, uint64(1), p.Version())
	assert.Equal(t, "a", p.Load().GetString("host"))
}

func TestPublisherCandidateConsumedOnce(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, nil)
	require.NoError(t, err)

	candidate, err := p.Build(context.Background())
	require.NoError(t, err)

	_, err = candidate.Publish(context.Background())
	require.NoError(t, err)

	_, err = candidate.Publish(context.Background())
	require.ErrorIs(t, err, ErrCandidateConsumed)
}

func TestSnapshotUnmarshal(t *testing.T) {
	v := New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	p, err := NewPublisher(v, nil)
	require.NoError(t, err)

	var cfg struct {
		Host string
		Port int
	}
	require.NoError(t, p.Load().Unmarshal(&cfg))
	assert.Equal(t, "a", cfg.Host)
	assert.Equal(t, 80, cfg.Port)
}
