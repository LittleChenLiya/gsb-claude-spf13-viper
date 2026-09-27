package viper_test

import (
	"fmt"

	viper "github.com/spf13/viper"
)

// ExampleNotifier demonstrates snapshot-based change notifications: subtree
// versus exact-path subscriptions, source-only changes staying silent and
// each delivered change carrying a monotonic version plus changed paths
// (without values).
func ExampleNotifier() {
	v := viper.New()
	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5432)
	v.SetDefault("log.level", "info")

	notifier := viper.NewNotifier(v, func(sub *viper.Subscription, err error) {
		fmt.Println("callback error:", err)
	})
	notifier.Commit() // publish the baseline snapshot as version 1

	dbSub := notifier.SubscribeSubtree("db", func(change viper.Change) {
		fmt.Printf("db subtree v%d changed: %v\n", change.Version, change.ChangedPaths)
	})
	defer dbSub.Unsubscribe()

	logSub := notifier.Subscribe("LOG.LEVEL", func(change viper.Change) {
		fmt.Printf("log.level v%d changed: %v\n", change.Version, change.ChangedPaths)
	})
	defer logSub.Unsubscribe()

	// Only db.port moves: the exact log.level subscription stays silent.
	v.Set("db.port", 6543)
	notifier.Commit()

	// Same effective value from a different layer: no notification.
	v.SetDefault("db.port", 5432)
	notifier.Commit()

	// Normalized upper-case subscription still receives the change.
	v.Set("log.level", "debug")
	notifier.Commit()

	version, snapshot := notifier.Snapshot()
	fmt.Printf("published version %d, db.port=%v, log.level=%v\n",
		version, snapshot["db.port"], snapshot["log.level"])

	// Output:
	// db subtree v2 changed: [db.port]
	// log.level v3 changed: [log.level]
	// published version 3, db.port=6543, log.level=debug
}
