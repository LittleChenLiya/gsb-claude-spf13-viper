// Copyright © 2026.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"context"
	"fmt"
	"sync"
)

// Validator checks a candidate configuration snapshot.
//
// Validate only receives the immutable [SnapshotView]: it cannot read the
// active Viper environment, environment variables, bound flags, files or
// remote stores, and it cannot mutate any configuration.
//
// Validate must honor ctx cancellation. A validator that returns nil after the
// pipeline context has been cancelled is treated as a late, ignored success:
// it never results in a publish.
type Validator interface {
	Validate(ctx context.Context, view SnapshotView) error
}

// ValidatorFunc adapts a plain function to the [Validator] interface.
type ValidatorFunc func(ctx context.Context, view SnapshotView) error

// Validate implements [Validator].
func (fn ValidatorFunc) Validate(ctx context.Context, view SnapshotView) error {
	return fn(ctx, view)
}

// Publisher is the publish hand-off used by [Pipeline].
//
// The default publisher calls [Candidate.Publish] on the validated candidate.
// Tests (or applications that want an extra release gate) can supply their own
// implementation. A publisher is invoked at most once per [Pipeline.Run], and
// only when every registered validator passed and the context is still alive.
type Publisher interface {
	Publish(candidate *Candidate) error
}

// defaultPublisher hands the validated snapshot to Candidate.Publish.
type defaultPublisher struct{}

func (defaultPublisher) Publish(c *Candidate) error { return c.Publish() }

// ValidatorResult is the outcome of a single validator.
type ValidatorResult struct {
	// Name is the registration name of the validator.
	Name string

	// Err is the error returned by the validator, nil on success.
	Err error

	// Panic captures a recovered validator panic, converted into an error so a
	// single faulty validator cannot crash the pipeline.
	Panic any
}

// OK reports whether the validator passed.
func (r ValidatorResult) OK() bool { return r.Err == nil && r.Panic == nil }

// Report is the aggregated outcome of a [Pipeline.Run].
type Report struct {
	// Results are always ordered by validator registration order, regardless
	// of the order the parallel validators actually finished in.
	Results []ValidatorResult

	// Canceled reports whether the pipeline (or a validator) observed
	// context cancellation before publication.
	Canceled bool

	// Published reports whether the publisher was invoked exactly once and
	// returned without error.
	Published bool

	// PublishErr holds an error returned by the publisher.
	PublishErr error
}

// OK reports whether every validator passed, the context was not canceled and
// the snapshot was successfully handed off to the publisher.
func (r *Report) OK() bool {
	if r == nil || r.Canceled || r.PublishErr != nil {
		return false
	}
	for _, res := range r.Results {
		if !res.OK() {
			return false
		}
	}
	return r.Published
}

// FailedErrors returns the non-nil validator errors (panic failures included)
// in registration order.
func (r *Report) FailedErrors() []error {
	var errs []error
	for _, res := range r.Results {
		switch {
		case res.Panic != nil:
			errs = append(errs, fmt.Errorf("validator %q panicked: %v", res.Name, res.Panic))
		case res.Err != nil:
			errs = append(errs, fmt.Errorf("validator %q: %w", res.Name, res.Err))
		}
	}
	return errs
}

// Pipeline is an explicit, one-shot validation pipeline for a candidate
// configuration snapshot.
//
// Registered validators are independent and run in parallel goroutines, but the
// aggregated [Report] is always presented in registration order. The candidate
// is handed to the publisher only when ALL validators pass and the context is
// still active:
//
//   - if any validator fails, the publisher is never called and the active
//     Viper values are untouched;
//   - if the context is canceled (or expires) before all validators are done,
//     the publisher is never called, even when validators report success
//     afterwards ("late success");
//   - file watching never triggers the pipeline and validated snapshots never
//     apply themselves automatically: publication is an explicit, single call.
type Pipeline struct {
	candidate  *Candidate
	publisher  Publisher
	validators []namedValidator
}

type namedValidator struct {
	name string
	run  Validator
}

// NewPipeline creates a validation pipeline bound to a parsed candidate.
//
// By default the pipeline publishes via [Candidate.Publish]. Use [WithPublisher]
// to override the publish hand-off (for example to record publish attempts in
// tests).
func NewPipeline(candidate *Candidate, opts ...PipelineOption) *Pipeline {
	p := &Pipeline{
		candidate: candidate,
		publisher: defaultPublisher{},
	}
	for _, opt := range opts {
		opt.applyPipeline(p)
	}
	return p
}

// PipelineOption customizes a [Pipeline].
type PipelineOption interface {
	applyPipeline(*Pipeline)
}

type pipelineOptionFunc func(*Pipeline)

func (fn pipelineOptionFunc) applyPipeline(p *Pipeline) { fn(p) }

// WithPublisher overrides the publish hand-off invoked after every validator
// passes. Passing nil leaves the default [Candidate.Publish] hand-off in place.
func WithPublisher(publisher Publisher) PipelineOption {
	return pipelineOptionFunc(func(p *Pipeline) {
		if publisher != nil {
			p.publisher = publisher
		}
	})
}

// Register adds a validator to the pipeline. The optional name is used in the
// [Report]; when omitted, a name based on the registration position is used.
// Register is not safe to use concurrently with Run.
func (p *Pipeline) Register(validator Validator, name ...string) *Pipeline {
	label := fmt.Sprintf("validator-%d", len(p.validators)+1)
	if len(name) > 0 && name[0] != "" {
		label = name[0]
	}
	p.validators = append(p.validators, namedValidator{name: label, run: validator})
	return p
}

// RegisterFunc is a convenience wrapper around [Pipeline.Register] for function
// validators.
func (p *Pipeline) RegisterFunc(name string, fn ValidatorFunc) *Pipeline {
	return p.Register(fn, name)
}

// Run executes every registered validator in parallel against an independent
// read-only view and aggregates the results in registration order.
//
// The publisher is invoked at most once, and only when all validators pass and
// ctx is still active. Run itself never returns a non-nil error; all failures,
// cancellations and publisher errors are reported through the returned
// [Report].
func (p *Pipeline) Run(ctx context.Context) *Report {
	results := make([]ValidatorResult, len(p.validators))

	var wg sync.WaitGroup
	for i, validator := range p.validators {
		wg.Add(1)
		go func(i int, validator namedValidator) {
			defer wg.Done()

			// Each validator gets its own defensive view: validators cannot
			// share or mutate state through their view, and nested values are
			// isolated copies.
			view := p.candidate.View()

			res := ValidatorResult{Name: validator.name}
			defer func() {
				if rec := recover(); rec != nil {
					res.Panic = rec
				}
				results[i] = res
			}()

			res.Err = validator.run.Validate(ctx, view)
		}(i, validator)
	}
	wg.Wait()

	report := &Report{Results: results}

	// Cancellation is checked after every validator has settled: a late
	// success arriving after cancel must never reach the publisher.
	if err := ctx.Err(); err != nil {
		report.Canceled = true
		return report
	}

	for _, res := range results {
		if !res.OK() {
			return report
		}
	}

	// All validators passed and the context is alive: this is the single
	// publish hand-off to the caller's publisher.
	if err := p.publisher.Publish(p.candidate); err != nil {
		report.PublishErr = err
		return report
	}
	report.Published = true

	return report
}
