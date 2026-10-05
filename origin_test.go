// Copyright © 2024 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spf13/viper"
)

// TestGetWithOrigin_EachLayer verifies that each configuration layer reports
// the correct origin when it is the winning source.
func TestGetWithOrigin_EachLayer(t *testing.T) {
	// Default layer
	v := viper.New()
	v.SetDefault("k", "d")
	val, origin, exists := v.GetWithOrigin("k")
	assert.Equal(t, "d", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginDefault, origin)
	assert.Equal(t, "default", origin.String())
	assert.Equal(t, v.Get("k"), val)

	// Config file layer
	v = viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("k: c\n")))
	val, origin, exists = v.GetWithOrigin("k")
	assert.Equal(t, "c", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginConfig, origin)
	assert.Equal(t, "config", origin.String())
	assert.Equal(t, v.Get("k"), val)

	// Environment layer
	v = viper.New()
	require.NoError(t, v.BindEnv("k"))
	t.Setenv("K", "e")
	val, origin, exists = v.GetWithOrigin("k")
	assert.Equal(t, "e", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginEnv, origin)
	assert.Equal(t, "env", origin.String())
	assert.Equal(t, v.Get("k"), val)

	// Flag layer (flag has been explicitly set)
	v = viper.New()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("k", "flag-default", "usage")
	require.NoError(t, fs.Set("k", "f"))
	require.NoError(t, v.BindPFlags(fs))
	val, origin, exists = v.GetWithOrigin("k")
	assert.Equal(t, "f", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginFlag, origin)
	assert.Equal(t, "flag", origin.String())
	assert.Equal(t, v.Get("k"), val)

	// Flag layer (flag left at its default): still reports the flag origin.
	v = viper.New()
	fs = pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("kd", "flag-default", "usage")
	require.NoError(t, v.BindPFlags(fs))
	val, origin, exists = v.GetWithOrigin("kd")
	assert.Equal(t, "flag-default", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginFlag, origin)
	assert.Equal(t, v.Get("kd"), val)

	// Override (explicit Set) layer
	v = viper.New()
	v.Set("k", "o")
	val, origin, exists = v.GetWithOrigin("k")
	assert.Equal(t, "o", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginOverride, origin)
	assert.Equal(t, "override", origin.String())
	assert.Equal(t, v.Get("k"), val)
}

// TestGetWithOrigin_Layers verifies that when the same key is set in several
// layers, the origin is the highest-priority layer and the value matches Get.
func TestGetWithOrigin_Layers(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("k: config\n")))
	v.SetDefault("k", "default")
	v.Set("k", "override")

	val, origin, exists := v.GetWithOrigin("k")
	assert.Equal(t, "override", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginOverride, origin)
	assert.Equal(t, v.Get("k"), val)

	// Remove the override: the config file should now win.
	v.Set("k", nil)
	val, origin, exists = v.GetWithOrigin("k")
	assert.Equal(t, "config", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginConfig, origin)
	assert.Equal(t, v.Get("k"), val)
}

// TestGetWithOrigin_Alias verifies that an alias is resolved to its real key
// before the origin is determined, following the original alias rules.
func TestGetWithOrigin_Alias(t *testing.T) {
	v := viper.New()
	v.Set("real", "value")
	v.RegisterAlias("alias", "real")

	val, origin, exists := v.GetWithOrigin("alias")
	assert.Equal(t, "value", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginOverride, origin)
	assert.Equal(t, v.Get("alias"), val)

	// A config value stored under the alias name is moved to the real key,
	// so both names report the same origin.
	v = viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("aliased: fromfile\n")))
	v.RegisterAlias("aliasname", "aliased")
	val, origin, exists = v.GetWithOrigin("aliasname")
	assert.Equal(t, "fromfile", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginConfig, origin)
	assert.Equal(t, v.Get("aliasname"), val)
}

// TestGetWithOrigin_Absent verifies that a key set in no layer reports absent.
func TestGetWithOrigin_Absent(t *testing.T) {
	v := viper.New()
	val, origin, exists := v.GetWithOrigin("missing")
	assert.Nil(t, val)
	assert.False(t, exists)
	assert.Equal(t, viper.OriginAbsent, origin)
	assert.Equal(t, "absent", origin.String())
	assert.Nil(t, v.Get("missing"))
}

// TestGetWithOrigin_NestedShadowing verifies that when a nested key is hidden
// by a parent value in a higher-priority layer, the origin locates the layer
// that actually causes the replacement.
func TestGetWithOrigin_NestedShadowing(t *testing.T) {
	// A leaf parent in the override layer shadows a nested config value.
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("a:\n  b:\n    c: 1\n")))
	v.Set("a.b", "leaf") // override parent is a scalar value
	val, origin, exists := v.GetWithOrigin("a.b.c")
	assert.Nil(t, val)
	assert.False(t, exists)
	assert.Equal(t, viper.OriginOverride, origin, "the override parent replaces the nested key")
	assert.Nil(t, v.Get("a.b.c"))

	// A leaf parent in the config layer shadows a nested default value.
	v = viper.New()
	v.SetDefault("a.b.c", 1)
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("a:\n  b: leaf\n")))
	val, origin, exists = v.GetWithOrigin("a.b.c")
	assert.Nil(t, val)
	assert.False(t, exists)
	assert.Equal(t, viper.OriginConfig, origin, "the config parent replaces the nested default")
	assert.Nil(t, v.Get("a.b.c"))

	// A leaf parent in the env layer (via automatic env) shadows a nested
	// config value.
	v = viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("a:\n  b:\n    c: 1\n")))
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	t.Setenv("A_B", "leaf")
	val, origin, exists = v.GetWithOrigin("a.b.c")
	assert.Nil(t, val)
	assert.False(t, exists)
	assert.Equal(t, viper.OriginEnv, origin, "the env parent replaces the nested config value")
	assert.Nil(t, v.Get("a.b.c"))
}

// TestGetWithOrigin_NestedMapParent verifies that a parent which is itself a
// map (rather than a leaf value) does NOT shadow a deeper key; the lookup
// falls through to the next layer.
func TestGetWithOrigin_NestedMapParent(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("a:\n  b:\n    c: 1\n    d: 2\n")))
	v.Set("a.b", map[string]any{"d": 3}) // override parent is a map, not a leaf

	val, origin, exists := v.GetWithOrigin("a.b.c")
	assert.Equal(t, 1, val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginConfig, origin, "a map parent must not shadow a deeper key")
	assert.Equal(t, v.Get("a.b.c"), val)

	// The override still wins for the key it actually sets.
	val, origin, exists = v.GetWithOrigin("a.b.d")
	assert.Equal(t, 3, val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginOverride, origin)
	assert.Equal(t, v.Get("a.b.d"), val)
}

// TestGetWithOrigin_EmptyEnv documents and verifies the empty-environment
// policy. By default (AllowEmptyEnv == false) an environment variable that is
// set but empty is treated as unset, so the value falls through to the next
// layer. With AllowEmptyEnv(true) the empty variable is considered set and
// wins. The origin therefore changes with the policy, which is intentional:
// the policy decides whether an empty env var counts as a value.
func TestGetWithOrigin_EmptyEnv(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("name: config-name\n")))
	require.NoError(t, v.BindEnv("name"))
	t.Setenv("NAME", "")

	// Default policy: empty env var is ignored, config wins.
	val, origin, exists := v.GetWithOrigin("name")
	assert.Equal(t, "config-name", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginConfig, origin)
	assert.Equal(t, v.Get("name"), val)

	// AllowEmptyEnv(true): the empty env var now counts as set and wins.
	v.AllowEmptyEnv(true)
	val, origin, exists = v.GetWithOrigin("name")
	assert.Equal(t, "", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginEnv, origin)
	assert.Equal(t, v.Get("name"), val)
}

// TestGetWithOrigin_Sensitive verifies that sensitive mode withholds the
// actual value while still reporting existence and the winning origin.
func TestGetWithOrigin_Sensitive(t *testing.T) {
	v := viper.New()
	v.Set("password", "super-secret")

	// A normal call returns the value.
	val, origin, exists := v.GetWithOrigin("password")
	assert.Equal(t, "super-secret", val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginOverride, origin)

	// A sensitive call withholds the value but reports existence and origin.
	val, origin, exists = v.GetWithOrigin("password", viper.WithSensitive())
	assert.Nil(t, val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginOverride, origin)

	// A sensitive call for an absent key still reports absent.
	val, origin, exists = v.GetWithOrigin("missing", viper.WithSensitive())
	assert.Nil(t, val)
	assert.False(t, exists)
	assert.Equal(t, viper.OriginAbsent, origin)
}

// TestGetWithOrigin_ConsistentWithGet verifies that the value reported by
// GetWithOrigin always equals the value reported by Get, across keys and
// layers. This is guaranteed by sharing the same traversal.
func TestGetWithOrigin_ConsistentWithGet(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(`
a:
  b:
    c: 1
  d: x
list:
  - 1
  - 2
`)))
	v.SetDefault("a.b.c", 0)
	v.SetDefault("def", "d")
	require.NoError(t, v.BindEnv("env"))
	t.Setenv("ENV", "e")
	v.Set("ov", "o")

	keys := []string{"a.b.c", "a.b.d", "def", "env", "ov", "missing", "list", "a", "list.0"}
	for _, key := range keys {
		val, origin, exists := v.GetWithOrigin(key)
		assert.Equal(t, v.Get(key), val, "value mismatch for %q", key)
		assert.Equal(t, val != nil, exists, "exists mismatch for %q", key)
		assert.NotEqual(t, viper.Origin(255), origin, "origin out of range for %q", key)
	}
}

// TestGetWithOrigin_TypeByDefaultValue verifies that when type inference by
// default value is enabled, GetWithOrigin returns the same coerced value as
// Get while still reporting the actual winning origin.
func TestGetWithOrigin_TypeByDefaultValue(t *testing.T) {
	v := viper.New()
	v.SetTypeByDefaultValue(true)
	v.SetDefault("port", 8080)
	require.NoError(t, v.BindEnv("port"))
	t.Setenv("PORT", "443")

	val, origin, exists := v.GetWithOrigin("port")
	assert.Equal(t, 443, val)
	assert.True(t, exists)
	assert.Equal(t, viper.OriginEnv, origin)
	assert.Equal(t, v.Get("port"), val)
}

// ExampleGetWithOrigin_threeLayers demonstrates a three-layer configuration
// (defaults, config file, environment) and shows how GetWithOrigin reports the
// effective value and the layer that supplied it for each key.
func ExampleGetWithOrigin_threeLayers() {
	v := viper.New()
	v.SetConfigType("yaml")
	_ = v.ReadConfig(strings.NewReader(`
server:
  host: file.example.com
  port: 8080
`))

	// Layer 1: built-in defaults.
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 9000)
	v.SetDefault("server.timeout", 30)

	// Layer 3: environment variables (highest priority here).
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	_ = os.Setenv("SERVER_PORT", "443")
	defer os.Unsetenv("SERVER_PORT")
	v.AutomaticEnv()

	for _, key := range []string{"server.host", "server.port", "server.timeout", "server.missing"} {
		val, origin, exists := v.GetWithOrigin(key)
		fmt.Printf("%s: value=%v origin=%s exists=%v\n", key, val, origin, exists)
	}

	// Output:
	// server.host: value=file.example.com origin=config exists=true
	// server.port: value=443 origin=env exists=true
	// server.timeout: value=30 origin=default exists=true
	// server.missing: value=<nil> origin=absent exists=false
}
