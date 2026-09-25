// Command include demonstrates Viper's opt-in local include loader.
//
// Run it from the repository root with:
//
//	go run ./examples/include
//
// It first prints the merged configuration of config.yaml (which includes
// a.yaml and b.yaml, both including shared.yaml) and then the full include
// chain reported for a cycle.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	base := "examples/include/fixtures"

	fmt.Println("== merged values (shared <- a <- b <- config) ==")

	v := viper.NewWithOptions(viper.ExperimentalInclude())
	v.SetConfigFile(base + "/config.yaml")

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// encoding/json prints map keys in sorted order, so the output is stable.
	encoded, err := json.MarshalIndent(v.AllSettings(), "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(encoded))

	fmt.Println()
	fmt.Println("== cycle error chain ==")

	cyclic := viper.NewWithOptions(viper.ExperimentalInclude())
	cyclic.SetConfigFile(base + "/cycle/config.yaml")

	if err := cyclic.ReadInConfig(); err != nil {
		var includeErr viper.IncludeError
		if errors.As(err, &includeErr) {
			fmt.Println("chain:", includeErr.Chain)
		}

		fmt.Println("error:", err)

		return nil
	}

	return errors.New("expected a cycle error, got none")
}
