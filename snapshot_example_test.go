package viper_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

// ExamplePublisher demonstrates the explicit build/validate/publish flow:
// an invalid candidate is rejected without touching the published snapshot,
// a valid candidate bumps the version, and a previously loaded snapshot
// stays readable afterwards.
func ExamplePublisher() {
	v := viper.New()
	v.SetDefault("host", "a")
	v.SetDefault("port", 80)

	validate := func(settings map[string]any) error {
		if port, ok := settings["port"].(int); !ok || port < 0 {
			return errors.New("port must be a non-negative int")
		}
		return nil
	}

	publisher, err := viper.NewPublisher(v, validate)
	if err != nil {
		panic(err)
	}
	defer publisher.Close()

	initial := publisher.Load()
	fmt.Printf("initial: host=%s port=%d version=%d\n",
		initial.GetString("host"), initial.GetInt("port"), initial.Version())

	// A file-watch notification (or any other trigger) makes the
	// application build a candidate explicitly.
	v.Set("host", "b")
	v.Set("port", -1)

	candidate, err := publisher.Build(context.Background())
	if err != nil {
		panic(err)
	}
	if _, err := candidate.Publish(context.Background()); err != nil {
		fmt.Printf("candidate rejected: %v\n", err)
	}

	snap := publisher.Load()
	fmt.Printf("after rejection: host=%s port=%d version=%d\n",
		snap.GetString("host"), snap.GetInt("port"), snap.Version())

	// Fix the candidate and publish again: both fields change together.
	v.Set("port", 81)
	candidate, err = publisher.Build(context.Background())
	if err != nil {
		panic(err)
	}
	published, err := candidate.Publish(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Printf("published: version=%d\n", published.Version())

	snap = publisher.Load()
	fmt.Printf("current: host=%s port=%d version=%d\n",
		snap.GetString("host"), snap.GetInt("port"), snap.Version())

	fmt.Printf("old snapshot still readable: host=%s port=%d version=%d\n",
		initial.GetString("host"), initial.GetInt("port"), initial.Version())

	// Output:
	// initial: host=a port=80 version=1
	// candidate rejected: port must be a non-negative int
	// after rejection: host=a port=80 version=1
	// published: version=2
	// current: host=b port=81 version=2
	// old snapshot still readable: host=a port=80 version=1
}

