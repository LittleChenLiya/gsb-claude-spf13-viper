package viper_test

import (
	"bytes"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Explain shows the full source chain for a key: which source wins and
// which candidates are shadowed by it.
func ExampleViper_Explain() {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetDefault("port", 80)
	_ = v.ReadConfig(bytes.NewReader([]byte("port: 81")))
	_ = v.BindEnv("port", "EXPLAIN_DEMO_PORT")
	os.Setenv("EXPLAIN_DEMO_PORT", "82")
	defer os.Unsetenv("EXPLAIN_DEMO_PORT")
	v.Set("port", 83)

	exp := v.Explain("port")
	fmt.Println("key:", exp.Key)
	fmt.Println("winner:", exp.Source, "=", exp.Value)
	for _, c := range exp.Candidates {
		fmt.Printf("candidate: %s = %v (winner=%v)\n", c.Source, c.Value, c.Winner)
	}

	// Output:
	// key: port
	// winner: override = 83
	// candidate: override = 83 (winner=true)
	// candidate: env = 82 (winner=false)
	// candidate: config = 81 (winner=false)
	// candidate: default = 80 (winner=false)
}

// WithSensitiveKeys masks every candidate of a sensitive subtree, not just
// the winning value.
func ExampleViper_Explain_sensitive() {
	v := viper.New()
	v.SetDefault("db.password", "default-pw")
	v.Set("db.password", "s3cret")

	exp := v.Explain("db.password", viper.WithSensitiveKeys("db"))
	fmt.Println("value:", exp.Value)
	for _, c := range exp.Candidates {
		fmt.Printf("candidate: %s = %v (masked=%v)\n", c.Source, c.Value, c.Masked)
	}

	// Output:
	// value: ***
	// candidate: override = *** (masked=true)
	// candidate: default = *** (masked=true)
}
