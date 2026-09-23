package viper_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

// ExampleSnapshotPublisher walks through the explicit build/validate/publish
// flow: a rejected candidate, a successful publish bumping the version, and
// an old snapshot staying readable after being replaced.
func ExampleSnapshotPublisher() {
	ctx := context.Background()

	v := viper.New()
	v.Set("host", "a")
	v.Set("port", 80)

	validate := func(s *viper.Snapshot) error {
		if s.GetInt("port") < 0 {
			return fmt.Errorf("port must not be negative: %d", s.GetInt("port"))
		}
		return nil
	}

	publisher, err := viper.NewSnapshotPublisher(v, validate)
	if err != nil {
		panic(err)
	}
	defer publisher.Close()

	current := publisher.Load()
	fmt.Printf("initial: host=%s port=%d version=%d\n",
		current.GetString("host"), current.GetInt("port"), current.Version())

	// Keep a handle on the old snapshot to prove it stays readable.
	old := publisher.Load()

	// Candidate with an invalid port is rejected by the validator.
	v.Set("host", "b")
	v.Set("port", -1)
	candidate, err := publisher.Build(ctx)
	if err != nil {
		panic(err)
	}
	if _, err := candidate.Publish(ctx); err != nil {
		fmt.Printf("rejected: %v\n", err)
	}

	current = publisher.Load()
	fmt.Printf("after reject: host=%s port=%d version=%d\n",
		current.GetString("host"), current.GetInt("port"), current.Version())

	// Fix the port and publish: both fields change together, version bumps.
	v.Set("port", 81)
	candidate, err = publisher.Build(ctx)
	if err != nil {
		panic(err)
	}
	if _, err := candidate.Publish(ctx); err != nil {
		panic(err)
	}

	current = publisher.Load()
	fmt.Printf("after publish: host=%s port=%d version=%d\n",
		current.GetString("host"), current.GetInt("port"), current.Version())

	fmt.Printf("old snapshot still readable: host=%s port=%d version=%d\n",
		old.GetString("host"), old.GetInt("port"), old.Version())

	// A stale candidate cannot roll back a newer generation.
	v.Set("host", "c")
	stale, err := publisher.Build(ctx)
	if err != nil {
		panic(err)
	}
	v.Set("host", "d")
	fresh, err := publisher.Build(ctx)
	if err != nil {
		panic(err)
	}
	if _, err := fresh.Publish(ctx); err != nil {
		panic(err)
	}
	if _, err := stale.Publish(ctx); errors.Is(err, viper.ErrStaleSnapshotGeneration) {
		fmt.Println("stale candidate rejected: newer generation kept")
	}

	current = publisher.Load()
	fmt.Printf("final: host=%s port=%d version=%d\n",
		current.GetString("host"), current.GetInt("port"), current.Version())

	// Output:
	// initial: host=a port=80 version=1
	// rejected: port must not be negative: -1
	// after reject: host=a port=80 version=1
	// after publish: host=b port=81 version=2
	// old snapshot still readable: host=a port=80 version=1
	// stale candidate rejected: newer generation kept
	// final: host=d port=81 version=3
}
