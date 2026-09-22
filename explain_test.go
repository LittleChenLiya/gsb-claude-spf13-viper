package viper

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func candidateSources(exp *Explanation) []Source {
	sources := make([]Source, 0, len(exp.Candidates))
	for _, c := range exp.Candidates {
		sources = append(sources, c.Source)
	}

	return sources
}

func candidateFor(t *testing.T, exp *Explanation, source Source) Candidate {
	t.Helper()
	for _, c := range exp.Candidates {
		if c.Source == source {
			return c
		}
	}
	t.Fatalf("no candidate from source %q in %#v", source, exp.Candidates)

	return Candidate{}
}

func TestExplainPriorityChain(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	v.SetDefault("port", 80)
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte("port: 81"))))
	require.NoError(t, v.BindEnv("port", "VIPER_EXPLAIN_TEST_PORT"))
	t.Setenv("VIPER_EXPLAIN_TEST_PORT", "82")
	v.Set("port", 83)

	exp := v.Explain("port")
	require.True(t, exp.Set)
	assert.Equal(t, "port", exp.Key)
	assert.Equal(t, SourceOverride, exp.Source)
	assert.Equal(t, 83, exp.Value)
	assert.Equal(t, 83, v.Get("port"))

	// Every layer shows up as a candidate, in priority order.
	require.Equal(t, []Source{SourceOverride, SourceEnv, SourceConfig, SourceDefault}, candidateSources(exp))
	assert.True(t, candidateFor(t, exp, SourceOverride).Winner)
	assert.Equal(t, 83, candidateFor(t, exp, SourceOverride).Value)
	assert.Equal(t, "82", candidateFor(t, exp, SourceEnv).Value)
	assert.Equal(t, "VIPER_EXPLAIN_TEST_PORT", candidateFor(t, exp, SourceEnv).Key)
	assert.Equal(t, 81, candidateFor(t, exp, SourceConfig).Value)
	assert.Equal(t, 80, candidateFor(t, exp, SourceDefault).Value)

	// Clearing the Set() override lets the env candidate win.
	delete(v.override, "port")
	exp = v.Explain("port")
	assert.Equal(t, SourceEnv, exp.Source)
	assert.Equal(t, "82", exp.Value)

	// Clearing the env var lets the config file win.
	os.Unsetenv("VIPER_EXPLAIN_TEST_PORT")
	exp = v.Explain("port")
	assert.Equal(t, SourceConfig, exp.Source)
	assert.Equal(t, 81, exp.Value)
	assert.Equal(t, []Source{SourceConfig, SourceDefault}, candidateSources(exp))
}

func TestExplainAllowEmptyEnv(t *testing.T) {
	newViper := func() *Viper {
		v := New()
		v.SetConfigType("yaml")
		v.SetDefault("port", 80)
		require.NoError(t, v.ReadConfig(bytes.NewReader([]byte("port: 81"))))
		require.NoError(t, v.BindEnv("port", "VIPER_EXPLAIN_TEST_EMPTY_PORT"))

		return v
	}
	t.Setenv("VIPER_EXPLAIN_TEST_EMPTY_PORT", "")

	// Default policy: an empty env var is ignored, config wins.
	v := newViper()
	exp := v.Explain("port")
	assert.Equal(t, SourceConfig, exp.Source)
	assert.Equal(t, 81, exp.Value)
	assert.Equal(t, []Source{SourceConfig, SourceDefault}, candidateSources(exp))

	// AllowEmptyEnv: the empty env var wins.
	v = newViper()
	v.AllowEmptyEnv(true)
	exp = v.Explain("port")
	assert.Equal(t, SourceEnv, exp.Source)
	assert.Equal(t, "", exp.Value)
	assert.Equal(t, "", v.Get("port"))
}

func TestExplainParentScalarBlocksChild(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte("app:\n  port: 81\n"))))
	v.Set("app", "scalar")

	exp := v.Explain("app.port")
	assert.False(t, exp.Set)
	assert.Nil(t, v.Get("app.port"))
	assert.Equal(t, "app", exp.BlockedBy)
	assert.Equal(t, SourceOverride, exp.BlockedAt)

	// The blocked config candidate is still listed, with the blocking site.
	config := candidateFor(t, exp, SourceConfig)
	assert.Equal(t, 81, config.Value)
	assert.Equal(t, "app", config.BlockedBy)
	assert.Equal(t, SourceOverride, config.BlockedAt)
	assert.False(t, config.Winner)
}

func TestExplainAliasChainAndCycle(t *testing.T) {
	v := New()
	v.Set("port", 83)
	v.RegisterAlias("myport", "port")

	exp := v.Explain("MyPort")
	assert.Equal(t, "myport", exp.RequestedKey)
	assert.Equal(t, "port", exp.Key)
	assert.Equal(t, []string{"myport", "port"}, exp.AliasChain)
	assert.Equal(t, SourceOverride, exp.Source)
	assert.Equal(t, 83, exp.Value)

	// A multi-hop chain resolves to the final key.
	v.RegisterAlias("listenport", "myport")
	exp = v.Explain("listenport")
	assert.Equal(t, "port", exp.Key)
	assert.Equal(t, []string{"listenport", "myport", "port"}, exp.AliasChain)

	// A cycle (not constructible through RegisterAlias) terminates instead
	// of recursing forever.
	v2 := New()
	v2.aliases["a"] = "b"
	v2.aliases["b"] = "a"
	exp = v2.Explain("a")
	assert.True(t, exp.AliasCycle)
	assert.False(t, exp.Set)
}

func TestExplainDottedLiteralKey(t *testing.T) {
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte("{\"a.b\": 5}"))))

	exp := v.Explain("a.b")
	require.True(t, exp.Set)
	assert.Equal(t, SourceConfig, exp.Source)
	assert.Equal(t, v.Get("a.b"), exp.Value)
	assert.Equal(t, "a.b", candidateFor(t, exp, SourceConfig).Key)
}

func TestExplainSensitiveSubtree(t *testing.T) {
	v := New()
	v.SetDefault("db.password", "default-pw")
	v.Set("db.password", "s3cret")
	v.Set("db.host", "localhost")
	v.Set("port", 83)

	exp := v.Explain("db.password", WithSensitiveKeys("db"))
	require.True(t, exp.Set)
	assert.Equal(t, maskedValue, exp.Value)
	require.Len(t, exp.Candidates, 2)
	for _, c := range exp.Candidates {
		assert.True(t, c.Masked)
		assert.Equal(t, maskedValue, c.Value)
	}

	// The whole subtree is masked.
	exp = v.Explain("db.host", WithSensitiveKeys("db"))
	assert.Equal(t, maskedValue, exp.Value)

	// Keys outside the subtree are left alone.
	exp = v.Explain("port", WithSensitiveKeys("db"))
	assert.Equal(t, 83, exp.Value)
	assert.False(t, candidateFor(t, exp, SourceOverride).Masked)
}

func TestExplainResultIsolation(t *testing.T) {
	v := New()
	v.Set("obj", map[string]any{"k": "v", "nested": map[string]any{"x": 1}})
	v.SetDefault("obj", map[string]any{"k": "default"})

	exp := v.Explain("obj")
	exp.Value.(map[string]any)["k"] = "hacked"
	exp.Value.(map[string]any)["nested"].(map[string]any)["x"] = 2
	for i := range exp.Candidates {
		exp.Candidates[i].Value.(map[string]any)["k"] = "hacked"
	}

	got := v.Get("obj").(map[string]any)
	assert.Equal(t, "v", got["k"])
	assert.Equal(t, 1, got["nested"].(map[string]any)["x"])
	assert.Equal(t, "default", v.searchMap(v.defaults, []string{"obj"}).(map[string]any)["k"])
}

func TestExplainMatchesGet(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	v.SetDefault("port", 80)
	v.SetDefault("nested.deep", "fallback")
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte("port: 81\nnested:\n  deep: file\n"))))
	require.NoError(t, v.BindEnv("port", "VIPER_EXPLAIN_TEST_MATCH_PORT"))
	t.Setenv("VIPER_EXPLAIN_TEST_MATCH_PORT", "82")
	v.Set("overrideonly", "yes")
	v.RegisterAlias("aliasport", "port")

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Int("flagport", 8080, "")
	require.NoError(t, flags.Parse([]string{"--flagport=90"}))
	require.NoError(t, v.BindPFlags(flags))

	for _, key := range []string{
		"port", "aliasport", "nested.deep", "overrideonly", "flagport", "missing",
	} {
		exp := v.Explain(key)
		assert.Equal(t, v.Get(key), exp.Value, "key %q", key)
		assert.Equal(t, v.Get(key) != nil, exp.Set, "key %q", key)
		if exp.Set {
			assert.NotEmpty(t, exp.Source, "key %q", key)
		}
	}

	// The unchanged flag only contributes its default value.
	flags2 := pflag.NewFlagSet("test2", pflag.ContinueOnError)
	flags2.Int("quiet", 42, "")
	require.NoError(t, flags2.Parse(nil))
	require.NoError(t, v.BindPFlags(flags2))
	exp := v.Explain("quiet")
	assert.Equal(t, SourceFlagDefault, exp.Source)
	assert.Equal(t, 42, exp.Value)
	assert.Equal(t, v.Get("quiet"), exp.Value)
}

func TestExplainAll(t *testing.T) {
	v := New()
	v.SetDefault("port", 80)
	v.Set("host", "localhost")
	v.AutomaticEnv()
	t.Setenv("VIPER_EXPLAIN_TEST_ALL_A", "1")
	t.Setenv("VIPER_EXPLAIN_TEST_ALL_B", "2")
	require.NoError(t, v.BindEnv("keya", "VIPER_EXPLAIN_TEST_ALL_A"))
	require.NoError(t, v.BindEnv("keyb", "VIPER_EXPLAIN_TEST_ALL_B"))

	all := v.ExplainAll()
	require.Contains(t, all, "port")
	require.Contains(t, all, "host")
	require.Contains(t, all, "keya")
	require.Contains(t, all, "keyb")

	// One shared snapshot: both env-backed keys resolve consistently.
	assert.Equal(t, "1", all["keya"].Value)
	assert.Equal(t, "2", all["keyb"].Value)
	assert.Equal(t, SourceEnv, all["keya"].Source)
	assert.Equal(t, 80, all["port"].Value)
	assert.Equal(t, v.Get("host"), all["host"].Value)

	// Sensitive keys are masked across the whole result.
	v.Set("db.password", "s3cret")
	all = v.ExplainAll(WithSensitiveKeys("db"))
	assert.Equal(t, maskedValue, all["db.password"].Value)
}

func TestExplainEnvReplacerAndDelimiter(t *testing.T) {
	v := New()
	v.SetEnvPrefix("myapp")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	t.Setenv("MYAPP_A_B", "env-value")

	exp := v.Explain("a.b")
	require.True(t, exp.Set)
	assert.Equal(t, SourceEnv, exp.Source)
	assert.Equal(t, "env-value", exp.Value)
	assert.Equal(t, "MYAPP_A_B", candidateFor(t, exp, SourceEnv).Key)

	v2 := NewWithOptions(KeyDelimiter("::"))
	v2.Set("a::b", 1)
	exp = v2.Explain("a::b")
	require.True(t, exp.Set)
	assert.Equal(t, "a::b", exp.Key)
	assert.Equal(t, 1, exp.Value)
}

func TestExplainDoesNotMutateViper(t *testing.T) {
	v := New()
	v.Set("a.b.c", 1)
	before := v.AllSettings()
	v.Explain("a.b.c")
	v.ExplainAll()
	assert.True(t, reflect.DeepEqual(before, v.AllSettings()))
}
