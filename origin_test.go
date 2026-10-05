package viper

import (
	"bytes"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkOrigin compares GetWithOrigin against Get: the effective value and the
// winning origin must always agree.
func checkOrigin(t *testing.T, v *Viper, key string, want any, wantOrigin Source, wantExists bool) {
	t.Helper()

	gotValue, gotOrigin, gotExists := v.GetWithOrigin(key)

	assert.Equal(t, wantExists, gotExists, "exists mismatch for %q", key)
	assert.Equal(t, wantOrigin, gotOrigin, "origin mismatch for %q", key)

	if wantExists {
		assert.Equal(t, want, gotValue, "value mismatch for %q", key)
		// The reported value must be exactly what Get returns.
		assert.Equal(t, v.Get(key), gotValue, "GetWithOrigin value differs from Get for %q", key)
	} else {
		assert.Nil(t, gotValue, "missing key %q must not report a value", key)
		assert.Nil(t, v.Get(key), "Get must be nil for missing key %q", key)
	}
}

func TestGetWithOriginEachSource(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		v := New()
		v.SetDefault("name", "default-value")
		checkOrigin(t, v, "name", "default-value", SourceDefault, true)
	})

	t.Run("kvstore", func(t *testing.T) {
		v := New()
		v.SetDefault("name", "default-value")
		v.kvstore = map[string]any{"name": "kv-value"}
		checkOrigin(t, v, "name", "kv-value", SourceKVPStore, true)
	})

	t.Run("file", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"name":"file-value"}`)))
		v.SetDefault("name", "default-value")
		checkOrigin(t, v, "name", "file-value", SourceFile, true)
	})

	t.Run("env", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"name":"file-value"}`)))
		v.BindEnv("name")
		t.Setenv("NAME", "env-value")
		checkOrigin(t, v, "name", "env-value", SourceEnv, true)
	})

	t.Run("changed flag", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"port":8080}`)))

		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flags.Int("port", 1138, "port")
		require.NoError(t, flags.Parse([]string{"--port", "9090"}))
		require.NoError(t, v.BindPFlag("port", flags.Lookup("port")))

		checkOrigin(t, v, "port", 9090, SourceFlag, true)
	})

	t.Run("unchanged flag default with viper default", func(t *testing.T) {
		v := New()
		v.SetDefault("port", 1)

		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flags.Int("port", 1138, "port")
		require.NoError(t, v.BindPFlag("port", flags.Lookup("port")))

		// The flag has not been set on the command line. Viper defaults are
		// consulted before the flag's own default, so the explicit viper
		// default wins and the origin is the default layer.
		checkOrigin(t, v, "port", 1, SourceDefault, true)
	})

	t.Run("unchanged flag default alone", func(t *testing.T) {
		v := New()

		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flags.Int("port", 1138, "port")
		require.NoError(t, v.BindPFlag("port", flags.Lookup("port")))

		// With no other layer providing a value, the flag's own default wins
		// (last chance) and the origin is the flag layer.
		checkOrigin(t, v, "port", 1138, SourceFlag, true)
	})

	t.Run("override", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"name":"file-value"}`)))
		v.BindEnv("name")
		t.Setenv("NAME", "env-value")
		v.Set("name", "override-value")
		checkOrigin(t, v, "name", "override-value", SourceOverride, true)
	})

	t.Run("missing", func(t *testing.T) {
		v := New()
		value, origin, exists := v.GetWithOrigin("nope")
		assert.Nil(t, value)
		assert.Equal(t, SourceNone, origin)
		assert.False(t, exists)
	})
}

// newStacked builds a viper instance that has the same key set in the file,
// key/value store, default and env layers, plus a bound flag.
func newStacked(t *testing.T, changed bool) *Viper {
	t.Helper()

	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"name":"file"}`)))
	v.kvstore = map[string]any{"name": "kv"}
	v.SetDefault("name", "default")
	v.BindEnv("name")
	t.Setenv("NAME", "env")

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("name", "flag-default", "")
	if changed {
		require.NoError(t, flags.Parse([]string{"--name", "flag"}))
	}
	require.NoError(t, v.BindPFlag("name", flags.Lookup("name")))

	return v
}

// TestGetWithOriginSameKeyMultipleLayers stacks every layer for one key and
// removes them in priority order: at every step origin must match the value
// Get returns.
func TestGetWithOriginSameKeyMultipleLayers(t *testing.T) {
	t.Run("full stack with changed flag and override", func(t *testing.T) {
		v := newStacked(t, true)
		v.Set("name", "override")
		checkOrigin(t, v, "name", "override", SourceOverride, true)
	})

	t.Run("without override changed flag wins", func(t *testing.T) {
		v := newStacked(t, true)
		checkOrigin(t, v, "name", "flag", SourceFlag, true)
	})

	t.Run("without changed flag env wins", func(t *testing.T) {
		v := newStacked(t, false)
		checkOrigin(t, v, "name", "env", SourceEnv, true)
	})

	t.Run("empty env falls back to file by default", func(t *testing.T) {
		v := newStacked(t, false)
		// Bound env var set but empty: ignored for backward compatibility,
		// so the file layer wins.
		t.Setenv("NAME", "")
		checkOrigin(t, v, "name", "file", SourceFile, true)
	})

	t.Run("without file kvstore wins", func(t *testing.T) {
		v := newStacked(t, false)
		t.Setenv("NAME", "")
		v.config = map[string]any{}
		checkOrigin(t, v, "name", "kv", SourceKVPStore, true)
	})

	t.Run("without kvstore viper default outranks unchanged flag default", func(t *testing.T) {
		v := newStacked(t, false)
		t.Setenv("NAME", "")
		v.config = map[string]any{}
		v.kvstore = map[string]any{}
		// The explicit viper default is consulted before the unchanged flag's
		// own default value.
		checkOrigin(t, v, "name", "default", SourceDefault, true)

		delete(v.pflags, "name")
		checkOrigin(t, v, "name", "default", SourceDefault, true)
	})
}

// TestGetWithOriginAlias ensures aliases follow the existing alias rules: the
// lookup continues with the aliased (real) key and reports its origin.
func TestGetWithOriginAlias(t *testing.T) {
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"real":{"name":"file"}}`)))
	v.SetDefault("real.name", "default")
	v.RegisterAlias("alias", "real.name")

	checkOrigin(t, v, "alias", "file", SourceFile, true)

	// Overriding the alias overrides the real key.
	v.Set("alias", "override")
	checkOrigin(t, v, "alias", "override", SourceOverride, true)
	checkOrigin(t, v, "real.name", "override", SourceOverride, true)
}

// TestGetWithOriginNestedParentReplacement proves that when a non-map parent
// from a higher-priority layer replaces a whole subtree, the reported origin
// points at that parent layer (it cannot be derived from AllSettings, where
// the child simply disappeared).
func TestGetWithOriginNestedParentReplacement(t *testing.T) {
	t.Run("override scalar parent shadows file child", func(t *testing.T) {
		v := New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString("tom:\n  age: 30\n")))
		v.SetDefault("tom.age", 10)
		v.Set("tom", "boy")

		// "tom" itself comes from the override as a map-less scalar.
		checkOrigin(t, v, "tom", "boy", SourceOverride, true)
		// "tom.age" is gone: the override parent replaced the subtree, and
		// the origin explains which layer caused it.
		value, origin, exists := v.GetWithOrigin("tom.age")
		assert.Nil(t, value)
		assert.False(t, exists)
		assert.Equal(t, SourceOverride, origin)
		assert.Nil(t, v.Get("tom.age"))
	})

	t.Run("file scalar parent shadows default child", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"tom":"boy"}`)))
		v.SetDefault("tom.age", 10)

		value, origin, exists := v.GetWithOrigin("tom.age")
		assert.Nil(t, value)
		assert.False(t, exists)
		assert.Equal(t, SourceFile, origin)
	})

	t.Run("map parent does not shadow and child keeps its origin", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"tom":{"age":30}}`)))
		v.SetDefault("tom.size", 4)

		checkOrigin(t, v, "tom.age", float64(30), SourceFile, true)
		checkOrigin(t, v, "tom.size", 4, SourceDefault, true)
	})

	t.Run("bound env flat parent does not shadow (consistent with Get)", func(t *testing.T) {
		v := New()
		v.SetDefault("tom.age", 10)
		v.BindEnv("tom", "TOM")
		t.Setenv("TOM", "boy")

		// A bound environment variable is stored as a flat key. Viper's flat
		// map shadowing only considers bound flags (map[string]FlagValue); it
		// does not treat a flat env parent as replacing the nested subtree, so
		// the child key still resolves to the default layer exactly like Get.
		// GetWithOrigin mirrors that rather than inventing a new rule.
		checkOrigin(t, v, "tom.age", 10, SourceDefault, true)
	})

	t.Run("automatic env scalar parent shadows default child", func(t *testing.T) {
		v := New()
		v.AutomaticEnv()
		v.SetDefault("tom.age", 10)
		t.Setenv("TOM", "boy")

		value, origin, exists := v.GetWithOrigin("tom.age")
		assert.Nil(t, value)
		assert.False(t, exists)
		assert.Equal(t, SourceEnv, origin)
	})
}

// TestGetWithOriginEmptyEnv documents the empty environment variable policy:
// by default an empty env var is ignored and the lookup falls through to lower
// layers; AllowEmptyEnv(true) makes it win as SourceEnv with an empty value.
func TestGetWithOriginEmptyEnv(t *testing.T) {
	t.Run("empty env ignored by default falls back to file", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"type":"donut"}`)))
		v.BindEnv("type")
		t.Setenv("TYPE", "")

		// Backward compatibility: an empty env value is not a valid value, so
		// Viper keeps looking and the file layer wins.
		checkOrigin(t, v, "type", "donut", SourceFile, true)
	})

	t.Run("empty env wins with AllowEmptyEnv", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"type":"donut"}`)))
		v.AllowEmptyEnv(true)
		v.BindEnv("type")
		t.Setenv("TYPE", "")

		// Policy change: the empty environment variable is now a real value,
		// it wins over the file and the origin is unambiguously the env.
		checkOrigin(t, v, "type", "", SourceEnv, true)
	})
}

// TestGetWithOriginSensitive verifies that sensitive lookups never return the
// value while still reporting existence and the winning origin.
func TestGetWithOriginSensitive(t *testing.T) {
	t.Run("sensitive value hidden but origin reported", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"password":"file-secret"}`)))
		v.BindEnv("password")
		t.Setenv("PASSWORD", "env-secret")

		value, origin, exists := v.GetWithOrigin("password", GetSensitive())
		assert.Nil(t, value, "sensitive value must not be returned")
		assert.Equal(t, SourceEnv, origin)
		assert.True(t, exists)
		// The non-sensitive lookup still works exactly like Get.
		checkOrigin(t, v, "password", "env-secret", SourceEnv, true)
	})

	t.Run("sensitive missing key", func(t *testing.T) {
		v := New()
		value, origin, exists := v.GetWithOrigin("password", GetSensitive())
		assert.Nil(t, value)
		assert.Equal(t, SourceNone, origin)
		assert.False(t, exists)
	})

	t.Run("sensitive empty env with AllowEmptyEnv", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"token":"file-secret"}`)))
		v.AllowEmptyEnv(true)
		v.BindEnv("token")
		t.Setenv("TOKEN", "")

		value, origin, exists := v.GetWithOrigin("token", GetSensitive())
		assert.Nil(t, value)
		assert.Equal(t, SourceEnv, origin)
		assert.True(t, exists)
	})

	t.Run("sensitive shadowed child reports replacing origin", func(t *testing.T) {
		v := New()
		v.SetConfigType("json")
		require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"secret":{"key":"file-secret"}}`)))
		v.Set("secret", "override-secret")

		value, origin, exists := v.GetWithOrigin("secret.key", GetSensitive())
		assert.Nil(t, value)
		assert.False(t, exists)
		assert.Equal(t, SourceOverride, origin)
	})
}

// TestGetWithOriginTypeByDefaultValue makes sure the single lookup still
// applies the same default-driven type conversion Get uses.
func TestGetWithOriginTypeByDefaultValue(t *testing.T) {
	t.Run("int default coerces env string", func(t *testing.T) {
		v := New()
		v.SetTypeByDefaultValue(true)
		v.SetDefault("count", 0)
		v.BindEnv("count")
		t.Setenv("COUNT", "42")

		value, origin, exists := v.GetWithOrigin("count")
		require.True(t, exists)
		assert.Equal(t, SourceEnv, origin)
		assert.Equal(t, 42, value)
		assert.Equal(t, v.Get("count"), value)
	})

	t.Run("string slice default makes env a slice", func(t *testing.T) {
		v := New()
		v.SetTypeByDefaultValue(true)
		v.SetDefault("items", []string{"a"})
		v.BindEnv("items")
		t.Setenv("ITEMS", "a b c")

		value, origin, exists := v.GetWithOrigin("items")
		require.True(t, exists)
		assert.Equal(t, SourceEnv, origin)
		// cast.ToStringSlice splits on whitespace for space-separated input.
		assert.Equal(t, []string{"a", "b", "c"}, value)
		assert.Equal(t, v.Get("items"), value)
	})
}

// TestGetWithOriginSingleLookup guards that the origin is observed during the
// single layered lookup and is not reconstructed from the merged settings,
// where a nested file value and a default for the same nested key would be
// indistinguishable.
func TestGetWithOriginSingleLookup(t *testing.T) {
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(`{"datastore":{"metric":{"host":"127.0.0.1"}}}`)))
	v.SetDefault("datastore.metric.host", "0.0.0.0")

	checkOrigin(t, v, "datastore.metric.host", "127.0.0.1", SourceFile, true)
}
