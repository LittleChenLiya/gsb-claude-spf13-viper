package viper

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func candidateFor(exp Explanation, source ExplainSource) *ExplainCandidate {
	for i := range exp.Candidates {
		if exp.Candidates[i].Source == source {
			return &exp.Candidates[i]
		}
	}

	return nil
}

func TestExplainPriorityChain(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("port: 81\n")))
	v.SetDefault("port", 80)
	t.Setenv("VIPER_EXPLAIN_PORT", "82")
	require.NoError(t, v.BindEnv("port", "VIPER_EXPLAIN_PORT"))
	v.Set("port", 83)

	exp := v.Explain("PORT")
	require.True(t, exp.Found)
	assert.Equal(t, "port", exp.Key)
	assert.Equal(t, SourceOverride, exp.Source)
	assert.Equal(t, 83, exp.Value)
	// The explicit Set wins over env, config and default.
	assert.Equal(t, 83, v.Get("port"))

	require.NotNil(t, candidateFor(exp, SourceOverride))
	assert.Equal(t, "82", candidateFor(exp, SourceEnv).Value)
	assert.Equal(t, "VIPER_EXPLAIN_PORT", candidateFor(exp, SourceEnv).Detail)
	assert.Equal(t, 81, candidateFor(exp, SourceConfig).Value)
	assert.Equal(t, 80, candidateFor(exp, SourceDefault).Value)

	// Clear the Set: env now wins.
	delete(v.override, "port")
	exp = v.Explain("port")
	require.True(t, exp.Found)
	assert.Equal(t, SourceEnv, exp.Source)
	assert.Equal(t, "82", exp.Value)
	assert.Equal(t, 82, v.GetInt("port"))
}

func TestExplainEmptyEnvPolicy(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("port: 81\n")))
	v.SetDefault("port", 80)
	t.Setenv("VIPER_EXPLAIN_PORT", "")
	require.NoError(t, v.BindEnv("port", "VIPER_EXPLAIN_PORT"))

	// Empty env values are ignored by default: config wins.
	exp := v.Explain("port")
	require.True(t, exp.Found)
	assert.Equal(t, SourceConfig, exp.Source)
	assert.Equal(t, 81, exp.Value)
	envCand := candidateFor(exp, SourceEnv)
	require.NotNil(t, envCand)
	assert.False(t, envCand.Found)
	assert.Contains(t, envCand.Note, "AllowEmptyEnv")

	// AllowEmptyEnv flips the resolution to the (empty) env value.
	v.AllowEmptyEnv(true)
	exp = v.Explain("port")
	require.True(t, exp.Found)
	assert.Equal(t, SourceEnv, exp.Source)
	assert.Equal(t, "", exp.Value)
	assert.Equal(t, "", v.GetString("port"))
}

func TestExplainParentScalarBlocksChild(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("parent:\n  child: from-config\n")))
	v.SetDefault("parent.child", "from-default")
	v.Set("parent", "scalar")

	exp := v.Explain("parent.child")
	assert.False(t, exp.Found)
	assert.Nil(t, v.Get("parent.child"))

	// The blocked candidates point at the exact shadowing location.
	cfgCand := candidateFor(exp, SourceConfig)
	require.NotNil(t, cfgCand)
	assert.True(t, cfgCand.Shadowed)
	assert.Equal(t, "override:parent", cfgCand.BlockedBy)
	defCand := candidateFor(exp, SourceDefault)
	require.NotNil(t, defCand)
	assert.True(t, defCand.Shadowed)
	assert.Equal(t, "override:parent", defCand.BlockedBy)
}

func TestExplainAliasChainAndCycle(t *testing.T) {
	v := New()
	v.RegisterAlias("a", "b")
	v.RegisterAlias("b", "c")
	v.Set("c", "value")

	exp := v.Explain("a")
	require.True(t, exp.Found)
	assert.Equal(t, "c", exp.Key)
	assert.Equal(t, []string{"b", "c"}, exp.AliasChain)
	assert.Equal(t, "value", exp.Value)

	// RegisterAlias refuses to create a cycle; explanation still terminates.
	v.RegisterAlias("x", "y")
	v.RegisterAlias("y", "x") // rejected: circular
	exp = v.Explain("y")
	assert.Equal(t, "y", exp.Key)

	// Even a hand-crafted cycle in the alias table cannot hang Explain.
	v.aliases["loop1"] = "loop2"
	v.aliases["loop2"] = "loop1"
	exp = v.Explain("loop1")
	assert.Contains(t, []string{"loop1", "loop2"}, exp.Key)
}

func TestExplainDottedLiteralKey(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	// The config file contains a literal key with a dot in it.
	require.NoError(t, v.ReadConfig(strings.NewReader("foo.bar: 1\n")))

	exp := v.Explain("foo.bar")
	require.True(t, exp.Found)
	assert.Equal(t, SourceConfig, exp.Source)
	assert.Equal(t, 1, exp.Value)
	assert.Equal(t, 1, v.Get("foo.bar"))
}

func TestExplainSensitiveSubtree(t *testing.T) {
	v := New()
	v.SetDefault("secret.token", "default-token")
	v.Set("secret.token", "real-token")
	v.Set("public", "visible")

	exp := v.Explain("secret.token", WithSensitiveKeys("secret"))
	require.True(t, exp.Found)
	assert.True(t, exp.Sensitive)
	assert.Equal(t, RedactedValue, exp.Value)
	// Every candidate is redacted, not just the winning value.
	for _, c := range exp.Candidates {
		if c.Found {
			assert.Equal(t, RedactedValue, c.Value, "source %s", c.Source)
		}
	}

	// The parent of a sensitive subtree is redacted as a whole.
	exp = v.Explain("secret", WithSensitiveKeys("secret.token"))
	assert.True(t, exp.Sensitive)
	assert.Equal(t, RedactedValue, exp.Value)

	// Unrelated keys stay visible.
	exp = v.Explain("public", WithSensitiveKeys("secret"))
	assert.False(t, exp.Sensitive)
	assert.Equal(t, "visible", exp.Value)
}

func TestExplainDoesNotShareMutableState(t *testing.T) {
	v := New()
	v.Set("nested", map[string]any{"a": 1, "list": []any{1, 2}})

	exp := v.Explain("nested")
	require.True(t, exp.Found)

	// Mutating the returned value must not change later Gets.
	m, ok := exp.Value.(map[string]any)
	require.True(t, ok)
	m["a"] = 999
	m["list"].([]any)[0] = 999
	assert.Equal(t, 1, v.Get("nested.a"))

	// Same for candidate values.
	for _, c := range exp.Candidates {
		if cm, ok := c.Value.(map[string]any); ok {
			cm["a"] = -1
		}
	}
	assert.Equal(t, 1, v.Get("nested.a"))

	// And a fresh explanation is unaffected.
	exp = v.Explain("nested")
	assert.Equal(t, 1, exp.Value.(map[string]any)["a"])
}

func TestExplainAllUsesOneEnvSnapshot(t *testing.T) {
	v := New()
	v.SetDefault("one", "d1")
	v.SetDefault("two", "d2")
	t.Setenv("VIPER_EXPLAIN_ONE", "e1")
	t.Setenv("VIPER_EXPLAIN_TWO", "e2")
	require.NoError(t, v.BindEnv("one", "VIPER_EXPLAIN_ONE"))
	require.NoError(t, v.BindEnv("two", "VIPER_EXPLAIN_TWO"))

	all := v.ExplainAll()
	require.Contains(t, all, "one")
	require.Contains(t, all, "two")
	assert.Equal(t, "e1", all["one"].Value)
	assert.Equal(t, "e2", all["two"].Value)
	assert.Equal(t, SourceEnv, all["one"].Source)
	assert.Equal(t, SourceEnv, all["two"].Source)
}

func TestExplainAllRedactsSensitiveKeys(t *testing.T) {
	v := New()
	v.Set("secret.token", "real-token")
	v.Set("public", "visible")

	all := v.ExplainAll(WithSensitiveKeys("secret"))
	assert.Equal(t, RedactedValue, all["secret.token"].Value)
	assert.Equal(t, "visible", all["public"].Value)
}

func TestExplainFlagAndFlagDefault(t *testing.T) {
	v := New()
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Int("port", 9090, "port")
	require.NoError(t, v.BindPFlags(flags))

	// Unchanged flag: its default is the last-chance value.
	exp := v.Explain("port")
	require.True(t, exp.Found)
	assert.Equal(t, SourceFlagDefault, exp.Source)
	assert.Equal(t, 9090, exp.Value)
	assert.Equal(t, 9090, v.GetInt("port"))

	// Changed flag wins.
	require.NoError(t, flags.Set("port", "1234"))
	exp = v.Explain("port")
	require.True(t, exp.Found)
	assert.Equal(t, SourceFlag, exp.Source)
	assert.Equal(t, 1234, exp.Value)
	assert.Equal(t, "--port", candidateFor(exp, SourceFlag).Detail)
	assert.Equal(t, 1234, v.GetInt("port"))
}

func TestExplainAutomaticEnvAndReplacer(t *testing.T) {
	v := New()
	v.SetEnvPrefix("app")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetDefault("db.host", "localhost")
	t.Setenv("APP_DB_HOST", "db.internal")

	exp := v.Explain("db.host")
	require.True(t, exp.Found)
	assert.Equal(t, SourceEnv, exp.Source)
	assert.Equal(t, "db.internal", exp.Value)
	assert.Equal(t, "APP_DB_HOST", candidateFor(exp, SourceEnv).Detail)
	assert.Equal(t, "db.internal", v.GetString("db.host"))
}

func TestExplainMatchesGet(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("port: 81\nparent:\n  child: c\n")))
	v.SetDefault("port", 80)
	v.SetDefault("parent.child", "dc")
	t.Setenv("VIPER_EXPLAIN_PORT", "82")
	require.NoError(t, v.BindEnv("port", "VIPER_EXPLAIN_PORT"))
	v.Set("extra", "set")

	for _, key := range v.AllKeys() {
		exp := v.Explain(key)
		got := v.Get(key)
		if got == nil {
			assert.False(t, exp.Found, "key %s", key)
			continue
		}
		require.True(t, exp.Found, "key %s", key)
		assert.Equal(t, got, exp.Value, "key %s", key)
	}
}
