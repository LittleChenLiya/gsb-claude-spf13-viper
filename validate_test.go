// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshot_NestedValues(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")

	snap, err := v.SnapshotFromReader(strings.NewReader(`
a:
  b:
    c: 42
  name: nested
list:
  - one
  - two
`))
	require.NoError(t, err)

	// Nested values are covered by the read-only view.
	assert.Equal(t, 42, snap.Get("a.b.c"))
	assert.Equal(t, "nested", snap.Get("a.name"))
	assert.Equal(t, []any{"one", "two"}, snap.Get("list"))
	assert.Equal(t, "nested", snap.GetString("a.name"))
	assert.True(t, snap.IsSet("a.b.c"))
	assert.True(t, snap.InConfig("a.b.c"))
	assert.False(t, snap.IsSet("a.missing"))
	assert.Nil(t, snap.Get("a.missing"))
}

func TestSnapshot_Unmarshal(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")

	snap, err := v.SnapshotFromReader(strings.NewReader("name: app\nport: 8080\n"))
	require.NoError(t, err)

	var cfg struct {
		Name string `mapstructure:"name"`
		Port int    `mapstructure:"port"`
	}
	require.NoError(t, snap.Unmarshal(&cfg))
	assert.Equal(t, "app", cfg.Name)
	assert.Equal(t, 8080, cfg.Port)
}

func TestSnapshotFromReader_ParseError(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")

	_, err := v.SnapshotFromReader(strings.NewReader("invalid: [yaml"))
	assert.Error(t, err)
}

func TestSnapshotFromReader_NilReader(t *testing.T) {
	v := New()

	snap, err := v.SnapshotFromReader(nil)
	assert.Error(t, err)
	assert.Nil(t, snap)
}

func TestSnapshot_DoesNotAccessEnv(t *testing.T) {
	t.Setenv("SNAPTEST_FOO", "envvalue")

	v := New()
	v.SetConfigType("yaml")

	snap, err := v.SnapshotFromReader(strings.NewReader("foo: configvalue\n"))
	require.NoError(t, err)

	// Config value wins; the environment is never consulted.
	assert.Equal(t, "configvalue", snap.Get("foo"))

	// A key absent from config must not fall through to the environment.
	assert.Nil(t, snap.Get("snaptest_bar"))
}

func TestSnapshot_DoesNotReadActiveViper(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	v.Set("override_key", "active")

	snap, err := v.SnapshotFromReader(strings.NewReader("foo: configvalue\n"))
	require.NoError(t, err)

	// The snapshot must not see the active viper's overrides.
	assert.Nil(t, snap.Get("override_key"))
	assert.Equal(t, "configvalue", snap.Get("foo"))
}

func TestSnapshot_ParsedOnceSharedByValidators(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	var seen []*Snapshot
	var mu sync.Mutex
	p := NewPipeline().
		Add("a", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			mu.Lock()
			seen = append(seen, s)
			mu.Unlock()
			return nil
		})).
		Add("b", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			mu.Lock()
			seen = append(seen, s)
			mu.Unlock()
			return nil
		}))

	_, _ = p.Validate(context.Background(), snap)

	require.Len(t, seen, 2)
	assert.Same(t, snap, seen[0])
	assert.Same(t, snap, seen[1])
}

func TestPipeline_ResultsStableRegardlessOfCompletionOrder(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	release := make(chan struct{})
	bDone := make(chan struct{})

	p := NewPipeline().
		Add("slow", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			<-release
			return nil
		})).
		Add("fast", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			close(bDone)
			return nil
		}))

	done := make(chan struct{})
	var publish PublishFunc
	var results []ValidationResult
	go func() {
		defer close(done)
		publish, results = p.Validate(context.Background(), snap)
	}()

	<-bDone // the validator registered second finishes first
	close(release)
	<-done

	require.NotNil(t, publish)
	require.Len(t, results, 2)
	// Results are always in registration order, not completion order.
	assert.Equal(t, "slow", results[0].Name)
	assert.Equal(t, "fast", results[1].Name)
	assert.NoError(t, results[0].Err)
	assert.NoError(t, results[1].Err)
}

func TestPipeline_FailureDoesNotPublish(t *testing.T) {
	v := New()
	v.Set("key", "old")
	snap := v.SnapshotFromMap(map[string]any{"key": "new"})

	p := NewPipeline().
		Add("pass", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			return nil
		})).
		Add("fail", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			return errors.New("boom")
		}))

	publish, results := p.Validate(context.Background(), snap)

	assert.Nil(t, publish)
	require.Len(t, results, 2)
	assert.NoError(t, results[0].Err)
	assert.Error(t, results[1].Err)

	// The active viper is unchanged: a validation error never publishes.
	assert.Equal(t, "old", v.Get("key"))
}

func TestPipeline_PublishContract(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	v.Set("keep", "original") // an unrelated key must survive publishing

	snap, err := v.SnapshotFromReader(strings.NewReader("published: yes\n"))
	require.NoError(t, err)

	p := NewPipeline().Add("ok", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
		return nil
	}))

	publish, results := p.Validate(context.Background(), snap)
	require.NotNil(t, publish)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Err)

	require.NoError(t, publish(v))
	assert.Equal(t, "yes", v.Get("published"))
	// Publishing merges; it does not clobber unrelated active values.
	assert.Equal(t, "original", v.Get("keep"))
}

func TestPipeline_Empty(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	publish, results := NewPipeline().Validate(context.Background(), snap)
	require.NotNil(t, publish)
	assert.Empty(t, results)

	require.NoError(t, publish(v))
	assert.Equal(t, "v", v.Get("k"))
}

func TestPipeline_CanceledContextDoesNotPublish(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before validation even starts

	p := NewPipeline().Add("ok", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
		return nil
	}))

	publish, _ := p.Validate(ctx, snap)
	assert.Nil(t, publish)

	// Publish count is zero: the caller is never handed a publish func.
	count := 0
	if publish != nil {
		count++
		_ = publish(v)
	}
	assert.Equal(t, 0, count)
	assert.False(t, v.IsSet("k"))
}

func TestPipeline_LateSuccessAfterCancellationNotPublished(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	release := make(chan struct{})
	bDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	p := NewPipeline().
		Add("slow", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			<-release // succeeds late, after cancellation
			return nil
		})).
		Add("fast", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
			close(bDone)
			return nil
		}))

	done := make(chan struct{})
	var publish PublishFunc
	go func() {
		defer close(done)
		publish, _ = p.Validate(ctx, snap)
	}()

	<-bDone
	cancel()       // cancel while the slow validator is still running
	close(release) // the slow validator succeeds late
	<-done

	// Even though every validator eventually succeeded, the canceled
	// context prevents publication.
	assert.Nil(t, publish)
	assert.False(t, v.IsSet("k"))
}

func TestPipeline_PublishRechecksCancellation(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	ctx, cancel := context.WithCancel(context.Background())
	p := NewPipeline().Add("ok", ValidatorFunc(func(ctx context.Context, s *Snapshot) error {
		return nil
	}))

	publish, _ := p.Validate(ctx, snap)
	require.NotNil(t, publish)

	cancel() // canceled after aggregation, before the caller publishes
	err := publish(v)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, v.IsSet("k"))
}

func TestPipeline_PublishNilTarget(t *testing.T) {
	v := New()
	snap := v.SnapshotFromMap(map[string]any{"k": "v"})

	publish, _ := NewPipeline().Validate(context.Background(), snap)
	require.NotNil(t, publish)

	err := publish(nil)
	assert.Error(t, err)
	assert.False(t, v.IsSet("k"))
}
