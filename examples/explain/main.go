// Command explain demonstrates Viper's Explain and ExplainAll APIs.
//
// It runs fully offline: the config "file" is read from an in-memory
// reader and the environment variable is set by the program itself.
//
// Usage:
//
//	go run ./examples/explain
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func main() {
	v := viper.New()
	v.SetConfigType("yaml")

	// Layer the same key across four sources: default < config < env < Set.
	v.SetDefault("port", 80)
	if err := v.ReadConfig(strings.NewReader(
		"port: 81\n" +
			"db:\n" +
			"  host: localhost\n" +
			"secret:\n" +
			"  token: file-token\n",
	)); err != nil {
		panic(err)
	}
	os.Setenv("APP_PORT", "82")
	defer os.Unsetenv("APP_PORT")
	v.SetEnvPrefix("app")
	if err := v.BindEnv("port"); err != nil {
		panic(err)
	}
	v.Set("port", 83)

	// Source chain 1: Set (83) wins over env (82), config (81), default (80).
	fmt.Println("=== source chain: port ===")
	fmt.Print(v.Explain("port"))

	// Source chain 2: a nested key resolved from the config file only.
	fmt.Println("=== source chain: db.host ===")
	fmt.Print(v.Explain("db.host"))

	// Redaction counterexample: masking only the winning value would still
	// leak the token through shadowed candidates, so Explain redacts every
	// candidate of a sensitive key (and its whole subtree).
	fmt.Println("=== redaction: secret.token (sensitive subtree) ===")
	fmt.Print(v.Explain("secret.token", viper.WithSensitiveKeys("secret")))

	fmt.Println("=== counterexample: same key explained WITHOUT the sensitive option ===")
	fmt.Print(v.Explain("secret.token"))
}
