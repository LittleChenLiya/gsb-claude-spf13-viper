package viper_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// ExampleGetWithOrigin shows the same keys resolved across three
// configuration layers: defaults, a configuration file and environment
// variables. Each reported origin is the layer that actually won the lookup
// and agrees with the value Get would return.
func ExampleGetWithOrigin() {
	// Layer 1: defaults
	v := viper.New()
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.token", "")

	// Layer 2: configuration file
	v.SetConfigType("yaml")
	fileConfig := []byte(`
server:
  host: "config-host"
  port: 9090
  token: "file-secret"
`)
	if err := v.ReadConfig(bytes.NewReader(fileConfig)); err != nil {
		panic(err)
	}

	// Layer 3: environment variables
	v.SetEnvPrefix("MYAPP")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	_ = os.Setenv("MYAPP_SERVER_HOST", "env-host") // overrides the file value
	// MYAPP_SERVER_TOKEN is intentionally left unset

	for _, key := range []string{"server.host", "server.port", "server.token"} {
		value, origin, exists := v.GetWithOrigin(key)
		fmt.Printf("%s: %v (origin=%s, exists=%t)\n", key, value, origin, exists)
	}

	// Sensitive lookup: the secret value is redacted, but its presence and
	// origin are still reported.
	_, origin, exists := v.GetWithOrigin("server.token", viper.GetSensitive())
	fmt.Printf("server.token: <redacted> (origin=%s, exists=%t)\n", origin, exists)

	// Output:
	// server.host: env-host (origin=env, exists=true)
	// server.port: 9090 (origin=file, exists=true)
	// server.token: file-secret (origin=file, exists=true)
	// server.token: <redacted> (origin=file, exists=true)
}

// ExampleGetWithOrigin_nestedParentReplacement shows how a non-map value for a
// parent key from a higher-priority layer replaces the whole nested subtree.
// The child is not reachable anymore, but the reported origin still locates
// the layer that caused it instead of pretending the key never existed.
func ExampleGetWithOrigin_nestedParentReplacement() {
	v := viper.New()
	v.SetConfigType("json")
	if err := v.ReadConfig(bytes.NewReader([]byte(`{"server":{"host":"config-host"}}`))); err != nil {
		panic(err)
	}
	// A scalar override for "server" replaces the file's nested map.
	v.Set("server", "replaced")

	parent, parentOrigin, parentExists := v.GetWithOrigin("server")
	child, childOrigin, childExists := v.GetWithOrigin("server.host")
	fmt.Printf("server: %v (origin=%s, exists=%t)\n", parent, parentOrigin, parentExists)
	fmt.Printf("server.host: %v (origin=%s, exists=%t)\n", child, childOrigin, childExists)

	// Output:
	// server: replaced (origin=override, exists=true)
	// server.host: <nil> (origin=override, exists=false)
}
