// Command include demonstrates Viper's local include loader.
//
// Run it from anywhere with:
//
//	go run ./examples/include
//
// It prints the merged configuration of a root file that includes two
// sibling files (which both include a shared file), and then shows the full
// include chain reported for a cyclic include graph.
package main

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/viper"
)

//go:embed testdata
var fixtures embed.FS

func main() {
	dir, err := os.MkdirTemp("", "viper-include-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	entries, err := fixtures.ReadDir("testdata")
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range entries {
		data, err := fixtures.ReadFile("testdata/" + entry.Name())
		if err != nil {
			log.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0o644); err != nil {
			log.Fatal(err)
		}
	}

	// 1. Merged values: root includes a.yaml and b.yaml, both of which
	// include shared.yaml.
	v := viper.NewWithOptions(viper.WithIncludes())
	v.SetConfigFile(filepath.Join(dir, "root.yaml"))

	if err := v.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	settings := v.AllSettings()
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	fmt.Println("merged configuration (shared < a < b < root):")
	for _, key := range keys {
		fmt.Printf("  %s = %v\n", key, settings[key])
	}

	// 2. Cycle detection: the error reports the full include chain.
	cyclic := viper.NewWithOptions(viper.WithIncludes())
	cyclic.SetConfigFile(filepath.Join(dir, "cycle-a.yaml"))

	fmt.Println("cyclic include graph:")
	if err := cyclic.ReadInConfig(); err != nil {
		fmt.Printf("  %s\n", err)
	}
}
