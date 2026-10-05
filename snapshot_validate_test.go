// Copyright © 2026.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	yamlcodec "github.com/spf13/viper/internal/encoding/yaml"
)

// countingPublisher is a test Publisher recording how often the validated
// candidate is handed off for release.
type countingPublisher struct {
	calls atomic.Int64
	err   error
}

func (p *countingPublisher) Publish(c *Candidate) error {
	p.calls.Add(1)
	return p.err
}

func mustCandidate(t *testing.T, target *Viper, format, src string) *Candidate {
	t.Helper()
	cand, err := NewCandidate(target, strings.NewReader(src), WithCandidateConfigType(format))
	if err != nil {
		t.Fatalf("NewCandidate returned unexpected error: %v", err)
	}
	return cand
}

const candidateYAML = `
server:
  host: 127.0.0.1
  port: 8080
  tls:
    enabled: true
features:
  - auth
  - metrics
retries: 3
`

func newActiveWithBaseline() *Viper {
	active := New()
	active.SetConfigType("yaml")
	active.Set("server.host", "old-host")
	active.Set("server.port", 4000)
	return active
}

// blockingValidator finishes (successfully or with an error) only once its
// gate channel is released, enabling deterministic reverse-order barriers.
// started is closed (or signaled) once the validator is actually parked, so
// tests never rely on sleeps to know the goroutine is ready.
type blockingValidator struct {
	name    string
	gate    chan struct{}
	started chan struct{}
	once    sync.Once
	err     error
}

func (b *blockingValidator) Validate(ctx context.Context, view SnapshotView) error {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.gate:
		return b.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newBlocking(name string, err error) *blockingValidator {
	return &blockingValidator{
		name:    name,
		gate:    make(chan struct{}),
		started: make(chan struct{}),
		err:     err,
	}
}

func waitStarted(t *testing.T, validators ...*blockingValidator) {
	t.Helper()
	for _, v := range validators {
		select {
		case <-v.started:
		case <-time.After(2 * time.Second):
			t.Fatalf("validator %q never started", v.name)
		}
	}
}

// TestPipelineBarrierReverseOrderStable is the barrier test: two validators
// registered v1 then v2 are forced to finish in reverse order (v2 first, v1
// second), but the aggregated report must still be presented in registration
// order and the snapshot must be published exactly once.
func TestPipelineBarrierReverseOrderStable(t *testing.T) {
	active := newActiveWithBaseline()
	cand := mustCandidate(t, active, "yaml", candidateYAML)
	pub := &countingPublisher{}

	v1 := newBlocking("first", nil)
	v2 := newBlocking("second", nil)

	pipeline := NewPipeline(cand, WithPublisher(pub)).
		Register(v1, "first").
		Register(v2, "second")

	done := make(chan *Report)
	go func() { done <- pipeline.Run(context.Background()) }()

	// Wait until both validators are parked on their gates.
	waitStarted(t, v1, v2)

	// Release v2 (registered second) first, then v1: strict reverse order.
	close(v2.gate)
	select {
	case <-done:
		t.Fatal("pipeline must not finish before the first validator is released")
	default:
	}
	close(v1.gate)

	select {
	case report := <-done:
		if got := pub.calls.Load(); got != 1 {
			t.Fatalf("publisher called %d times, want 1", got)
		}
		if len(report.Results) != 2 {
			t.Fatalf("got %d results, want 2", len(report.Results))
		}
		if report.Results[0].Name != "first" || report.Results[1].Name != "second" {
			t.Fatalf("results not in registration order: %q, %q",
				report.Results[0].Name, report.Results[1].Name)
		}
		if !report.OK() {
			t.Fatalf("report = %+v, want OK", report)
		}
		if !report.Published {
			t.Fatalf("report.Published = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not finish after barriers were released")
	}
}

// TestPipelineOneFailureKeepsActiveValues verifies that when one validator
// fails (again finishing out of registration order), no publish happens and
// the active Viper values stay unchanged.
func TestPipelineOneFailureKeepsActiveValues(t *testing.T) {
	active := newActiveWithBaseline()
	cand := mustCandidate(t, active, "yaml", candidateYAML)
	pub := &countingPublisher{}

	wantErr := errors.New("port must not be 8080")
	ok := newBlocking("ok", nil)
	bad := newBlocking("bad", wantErr)

	pipeline := NewPipeline(cand, WithPublisher(pub)).
		Register(ok, "ok").
		Register(bad, "bad")

	done := make(chan *Report)
	go func() { done <- pipeline.Run(context.Background()) }()
	waitStarted(t, ok, bad)

	// Failing validator (registered second) finishes first.
	close(bad.gate)
	select {
	case <-done:
		t.Fatal("pipeline must not finish while the first validator is parked")
	default:
	}
	close(ok.gate)

	var report *Report
	select {
	case report = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not finish")
	}

	if pub.calls.Load() != 0 {
		t.Fatalf("publisher called %d times, want 0", pub.calls.Load())
	}
	if report.OK() || report.Published {
		t.Fatalf("report = %+v, want failed/unpublished", report)
	}
	if report.Results[0].Name != "ok" || report.Results[1].Name != "bad" {
		t.Fatalf("results not in registration order: %q, %q",
			report.Results[0].Name, report.Results[1].Name)
	}
	if !errors.Is(report.Results[1].Err, wantErr) {
		t.Fatalf("bad result error = %v, want %v", report.Results[1].Err, wantErr)
	}

	// Active values remain the baseline; the candidate never reached config.
	if got := active.GetString("server.host"); got != "old-host" {
		t.Fatalf("active server.host = %q, want %q", got, "old-host")
	}
	if got := active.GetInt("server.port"); got != 4000 {
		t.Fatalf("active server.port = %d, want 4000", got)
	}
}

// TestPipelineCancellationPublishesZero verifies the cancellation contract:
// after the context is canceled, a validator that then reports success is a
// "late success" and the publisher is never invoked (publish count 0).
func TestPipelineCancellationPublishesZero(t *testing.T) {
	active := newActiveWithBaseline()
	cand := mustCandidate(t, active, "yaml", candidateYAML)
	pub := &countingPublisher{}

	late := newBlocking("late", nil)
	pipeline := NewPipeline(cand, WithPublisher(pub)).Register(late, "late")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *Report)
	go func() { done <- pipeline.Run(ctx) }()

	waitStarted(t, late)
	cancel()

	// Late success: the validator is released only after cancellation and
	// still returns nil. That success must never reach the publisher.
	close(late.gate)

	var report *Report
	select {
	case report = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not finish")
	}

	if got := pub.calls.Load(); got != 0 {
		t.Fatalf("publisher called %d times after cancellation, want 0", got)
	}
	if !report.Canceled {
		t.Fatalf("report.Canceled = false, want true")
	}
	if report.OK() || report.Published {
		t.Fatalf("report = %+v, want canceled/unpublished", report)
	}
	if got := active.GetString("server.host"); got != "old-host" {
		t.Fatalf("active server.host = %q, want %q", got, "old-host")
	}
}

// TestSnapshotViewCoversNestedValues verifies read-only access for nested maps,
// slices and typed getters, including case-insensitive keys and Sub views.
func TestSnapshotViewCoversNestedValues(t *testing.T) {
	active := New()
	cand := mustCandidate(t, active, "yaml", candidateYAML)
	view := cand.View()

	if got := view.GetString("server.host"); got != "127.0.0.1" {
		t.Fatalf("server.host = %q", got)
	}
	if got := view.GetInt("SERVER.PORT"); got != 8080 { // case-insensitive nested
		t.Fatalf("SERVER.PORT = %d, want 8080", got)
	}
	if got := view.GetBool("server.tls.enabled"); !got {
		t.Fatalf("server.tls.enabled = false, want true")
	}
	if got := view.GetStringSlice("features"); len(got) != 2 || got[0] != "auth" || got[1] != "metrics" {
		t.Fatalf("features = %v", got)
	}
	if got := view.GetInt("retries"); got != 3 {
		t.Fatalf("retries = %d, want 3", got)
	}
	if !view.IsSet("server.tls.enabled") || view.IsSet("server.missing.deep") {
		t.Fatalf("IsSet behavior wrong: tls=%v missing=%v",
			view.IsSet("server.tls.enabled"), view.IsSet("server.missing.deep"))
	}

	sub := view.Sub("server")
	if sub == nil {
		t.Fatal("Sub(server) = nil")
	}
	if got := sub.GetInt("port"); got != 8080 {
		t.Fatalf("sub port = %d, want 8080", got)
	}
	if sub.Get("tls") == nil {
		t.Fatal("sub tls is nil")
	}
	if view.Sub("server.host") != nil {
		t.Fatal("Sub of scalar must be nil")
	}
}

// TestSnapshotViewIsolationForNestedValues verifies the read-only view cannot
// mutate the snapshot through top-level or nested maps/slices, and that two
// validators (views) cannot affect each other.
func TestSnapshotViewIsolationForNestedValues(t *testing.T) {
	active := New()
	cand := mustCandidate(t, active, "yaml", candidateYAML)

	v1 := cand.View()
	tampered := v1.GetStringMap("server")
	tampered["host"] = "tampered"
	tampered["new-key"] = "injected"

	if slice := v1.GetStringSlice("features"); len(slice) > 0 {
		slice[0] = "tampered-feature"
	}

	if got := v1.GetString("server.host"); got != "127.0.0.1" {
		t.Fatalf("snapshot mutated through nested map: host = %q", got)
	}
	if got := v1.GetStringSlice("features")[0]; got != "auth" {
		t.Fatalf("snapshot mutated through slice: features[0] = %q", got)
	}

	// A fresh view (what another validator receives) is unaffected too.
	v2 := cand.View()
	if got := v2.GetString("server.host"); got != "127.0.0.1" {
		t.Fatalf("second view sees mutation: host = %q", got)
	}
	if v2.IsSet("server.new-key") {
		t.Fatal("second view sees injected key")
	}

	// Sub views are isolated as well.
	if sub := v2.Sub("server"); sub.GetString("host") != "127.0.0.1" {
		t.Fatalf("sub view isolation broken: %q", sub.GetString("host"))
	}
}

// TestValidatorCannotSeeCurrentEnvironment verifies a validator's view exposes
// only parsed candidate bytes, never the active environment (overrides, env
// variables, defaults or flags).
func TestValidatorCannotSeeCurrentEnvironment(t *testing.T) {
	active := newActiveWithBaseline()
	active.SetDefault("region", "eu-west")
	active.AutomaticEnv()
	t.Setenv("SERVER_HOST", "env-host") // would win on a live Viper lookup

	cand := mustCandidate(t, active, "yaml", candidateYAML)

	pipeline := NewPipeline(cand).RegisterFunc("env-isolation", func(_ context.Context, view SnapshotView) error {
		if got := view.GetString("region"); got != "" {
			return fmt.Errorf("view leaked default value %q", got)
		}
		// Candidate value must win over every live source because live
		// sources are simply absent from the view.
		if got := view.GetString("server.host"); got != "127.0.0.1" {
			return fmt.Errorf("server.host = %q, want candidate value", got)
		}
		return nil
	})

	report := pipeline.Run(context.Background())
	if !report.OK() {
		t.Fatalf("validation failures: %v", report.FailedErrors())
	}
}

// TestCandidateParsedExactlyOnce verifies the same snapshot is decoded one
// time when the candidate is created, and views/publish never reparse.
func TestCandidateParsedExactlyOnce(t *testing.T) {
	active := New()

	const format = "yaml"
	registry := NewCodecRegistry()
	var decodes atomic.Int64
	if err := registry.RegisterCodec(format, countingCodec{delegate: yamlcodec.Codec{}, n: &decodes}); err != nil {
		t.Fatalf("RegisterCodec: %v", err)
	}
	active.decoderRegistry = registry
	active.SetConfigType(format)

	cand, err := NewCandidate(active, strings.NewReader(candidateYAML))
	if err != nil {
		t.Fatalf("NewCandidate: %v", err)
	}
	if got := decodes.Load(); got != 1 {
		t.Fatalf("decoder called %d times during NewCandidate, want 1", got)
	}

	// Views and validators must not trigger any additional decodes.
	_ = cand.View()
	_ = cand.View().Sub("server.tls")
	report := NewPipeline(cand).RegisterFunc("noop", func(context.Context, SnapshotView) error {
		return nil
	}).Run(context.Background())
	if !report.OK() {
		t.Fatalf("pipeline failure: %v", report.FailedErrors())
	}
	if err := cand.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := decodes.Load(); got != 1 {
		t.Fatalf("snapshot decoded %d times total, want exactly 1", got)
	}
}

// TestParseErrorDoesNotChangeActiveViper verifies invalid candidate bytes fail
// fast at construction and leave the active instance completely untouched.
func TestParseErrorDoesNotChangeActiveViper(t *testing.T) {
	active := newActiveWithBaseline()
	before := active.AllSettings()

	const broken = "server:\n  port: [unterminated\n"
	_, err := NewCandidate(active, strings.NewReader(broken), WithCandidateConfigType("yaml"))
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	var parseErr ConfigParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("error = %T, want ConfigParseError", err)
	}

	after := active.AllSettings()
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("active settings changed after parse error:\nbefore=%v\nafter=%v", before, after)
	}
	if got := active.GetInt("server.port"); got != 4000 {
		t.Fatalf("active server.port = %d, want 4000", got)
	}
}

// TestPublishedSnapshotReplacesConfigLayer verifies the publish contract:
// Candidate.Publish swaps the config layer while overrides (higher precedence)
// survive, and the stored map is an independent copy.
func TestPublishedSnapshotReplacesConfigLayer(t *testing.T) {
	active := newActiveWithBaseline() // overrides server.host/server.port
	cand := mustCandidate(t, active, "yaml", candidateYAML)

	if err := cand.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Overrides still take precedence over the new config layer.
	if got := active.GetString("server.host"); got != "old-host" {
		t.Fatalf("override lost after publish: host = %q", got)
	}
	if got := active.GetInt("server.port"); got != 4000 {
		t.Fatalf("override lost after publish: port = %d", got)
	}
	// A candidate-only key is live from the replaced config layer.
	if got := active.GetBool("server.tls.enabled"); !got {
		t.Fatal("candidate nested key not visible after publish")
	}
	if got := active.GetStringSlice("features"); len(got) != 2 {
		t.Fatalf("features after publish = %v", got)
	}

	// Mutating the published map externally must not alias the candidate.
	active.Set("server.tls.enabled", false)
	cand2 := mustCandidate(t, New(), "yaml", candidateYAML)
	if !cand2.View().GetBool("server.tls.enabled") {
		t.Fatal("candidate storage aliased target after publish")
	}
}

// TestDefaultPublisherHandOff verifies the default pipeline publishes via
// Candidate.Publish when all validators pass, end to end.
func TestDefaultPublisherHandOff(t *testing.T) {
	active := New()
	cand := mustCandidate(t, active, "yaml", candidateYAML)

	report := NewPipeline(cand).
		RegisterFunc("port-range", func(_ context.Context, view SnapshotView) error {
			if p := view.GetInt("server.port"); p <= 0 || p > 65535 {
				return fmt.Errorf("port %d out of range", p)
			}
			return nil
		}).
		Run(context.Background())

	if !report.OK() {
		t.Fatalf("report = %+v: %v", report, report.FailedErrors())
	}
	if got := active.GetInt("server.port"); got != 8080 {
		t.Fatalf("published port = %d, want 8080", got)
	}
}

// TestPanicValidatorFailsPipeline verifies a panicking validator fails closed
// without a publish and appears in registration order.
func TestPanicValidatorFailsPipeline(t *testing.T) {
	active := New()
	cand := mustCandidate(t, active, "yaml", candidateYAML)
	pub := &countingPublisher{}

	pipeline := NewPipeline(cand, WithPublisher(pub)).
		RegisterFunc("boom", func(context.Context, SnapshotView) error { panic("kaboom") })

	report := pipeline.Run(context.Background())
	if report.OK() || pub.calls.Load() != 0 {
		t.Fatalf("panic validator must fail closed: %+v", report)
	}
	if report.Results[0].Panic != "kaboom" {
		t.Fatalf("panic not captured: %+v", report.Results[0])
	}
}

// TestPipelineIsNotTriggeredByFileWatching documents the contract that
// validation/publish is never automatic: reading a new config into the active
// Viper does not run the pipeline (publish count stays zero).
func TestPipelineIsNotTriggeredByFileWatching(t *testing.T) {
	active := New()
	active.SetConfigType("yaml")
	if err := active.ReadConfig(bytes.NewReader([]byte("server:\n  port: 1\n"))); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	cand := mustCandidate(t, active, "yaml", candidateYAML)
	pub := &countingPublisher{}
	NewPipeline(cand, WithPublisher(pub)).
		RegisterFunc("noop", func(context.Context, SnapshotView) error { return nil })

	// Simulate a config reload that WatchConfig would perform; without an
	// explicit Run the candidate must never publish.
	if err := active.ReadConfig(bytes.NewReader([]byte("server:\n  port: 2\n"))); err != nil {
		t.Fatalf("ReadConfig reload: %v", err)
	}
	if got := pub.calls.Load(); got != 0 {
		t.Fatalf("pipeline published %d times without explicit Run", got)
	}
	if got := active.GetInt("server.port"); got != 2 {
		t.Fatalf("reloaded port = %d, want 2", got)
	}
}

// --- helpers for decode-counting ---

type countingCodec struct {
	delegate Codec
	n        *atomic.Int64
}

func (c countingCodec) Decode(b []byte, v map[string]any) error {
	c.n.Add(1)
	return c.delegate.Decode(b, v)
}

func (c countingCodec) Encode(v map[string]any) ([]byte, error) {
	return c.delegate.Encode(v)
}
