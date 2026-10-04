// Copyright © 2026 The Viper Authors.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findChange returns the Change for the given canonical key.
func findChange(t *testing.T, r *DiffReport, key string) Change {
	t.Helper()
	for _, c := range r.Changes {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("change for key %q not found", key)
	return Change{}
}

// TestDiffFileToEnv is the headline acceptance case: a key provided by the
// file layer first and by the environment later must show the file -> env
// transition together with the effective value change.
func TestDiffFileToEnv(t *testing.T) {
	before := NewSnapshot(
		map[string]any{},
		map[string]any{"port": 1},
		map[string]any{},
		map[string]any{},
	)
	after := NewSnapshot(
		map[string]any{},
		map[string]any{"port": 1},
		map[string]any{"port": "2"},
		map[string]any{},
	)

	report := before.Diff(after)
	c := findChange(t, report, "port")

	assert.True(t, c.Changed)
	assert.Equal(t, LayerFile, c.Before.Layer)
	assert.Equal(t, PresenceSet, c.Before.Presence)
	assert.Equal(t, 1, c.Before.Value)
	assert.Equal(t, LayerEnv, c.After.Layer)
	assert.Equal(t, PresenceSet, c.After.Presence)
	assert.Equal(t, "2", c.After.Value)

	// The per-layer records explain where every value comes from.
	assert.Equal(t, PresenceSet, c.BeforeLayers[LayerFile].Presence)
	assert.Equal(t, PresenceMissing, c.BeforeLayers[LayerEnv].Presence)
	assert.Equal(t, PresenceSet, c.AfterLayers[LayerFile].Presence)
	assert.Equal(t, PresenceSet, c.AfterLayers[LayerEnv].Presence)

	line := report.String()
	assert.Contains(t, line, "port: file(set=1) -> env(set=\"2\")")
	assert.Contains(t, line, "[effective: file -> env]")
}

// TestDiffSensitivePassword ensures secret values are never exported: the
// report only states the change and the source layers.
func TestDiffSensitivePassword(t *testing.T) {
	before := NewSnapshot(
		map[string]any{},
		map[string]any{"password": "file-secret"},
		map[string]any{},
		map[string]any{"password": "override-secret"},
	)
	after := NewSnapshot(
		map[string]any{},
		map[string]any{"password": "file-secret"},
		map[string]any{"password": "env-secret"},
		map[string]any{"password": "override-secret"},
	)

	report := before.Diff(after)
	c := findChange(t, report, "password")

	assert.True(t, c.Changed)
	assert.True(t, c.Sensitive)
	assert.Equal(t, LayerOverride, c.Before.Layer)
	assert.Equal(t, LayerOverride, c.After.Layer)
	assert.Equal(t, PresenceRedacted, c.Before.Presence)
	assert.Equal(t, PresenceRedacted, c.After.Presence)
	assert.Nil(t, c.Before.Value)
	assert.Nil(t, c.After.Value)

	for _, rec := range c.BeforeLayers {
		assert.Nil(t, rec.Value)
	}
	for _, rec := range c.AfterLayers {
		assert.Nil(t, rec.Value)
	}

	rendered := report.String()
	assert.NotContains(t, rendered, "file-secret")
	assert.NotContains(t, rendered, "override-secret")
	assert.NotContains(t, rendered, "env-secret")
	assert.Contains(t, rendered, "[sensitive]")

	// Explicit opt-in marking works the same as the default heuristic.
	report2 := before.Diff(after, DiffSensitiveKeys("password"))
	c2 := findChange(t, report2, "password")
	assert.True(t, c2.Sensitive)
	assert.Nil(t, c2.After.Value)
}

// TestEmptyValuesAreNotMissing distinguishes missing, null and empty string.
// An empty string is a real value and must shadow lower-priority layers.
func TestEmptyValuesAreNotMissing(t *testing.T) {
	s := NewSnapshot(
		map[string]any{"missing": 9, "empty": "default-empty", "nullish": "default-null"},
		map[string]any{"empty": "", "nullish": nil, "onlyempty": ""},
		map[string]any{},
		map[string]any{},
	)

	// Missing key in file falls through to the default.
	missing := s.Trace("missing")
	assert.Equal(t, PresenceMissing, missing.Layers[LayerFile].Presence)
	assert.Equal(t, PresenceSet, missing.Layers[LayerDefault].Presence)
	assert.Equal(t, LayerDefault, missing.Effective)
	assert.Equal(t, 9, missing.EffectiveValue)

	// Empty string in file wins over the default and is not reported missing.
	empty := s.Trace("empty")
	assert.Equal(t, PresenceEmpty, empty.Layers[LayerFile].Presence)
	assert.Equal(t, "", empty.Layers[LayerFile].Value)
	assert.Equal(t, LayerFile, empty.Effective)
	assert.Equal(t, PresenceEmpty, empty.EffectivePresence)
	assert.Equal(t, "", empty.EffectiveValue)

	// Null in file is recorded per-layer, but falls through like Viper.Get.
	nullish := s.Trace("nullish")
	assert.Equal(t, PresenceNull, nullish.Layers[LayerFile].Presence)
	assert.Nil(t, nullish.Layers[LayerFile].Value)
	assert.Equal(t, LayerDefault, nullish.Effective)
	assert.Equal(t, "default-null", nullish.EffectiveValue)

	// A key that is only an empty string with no default is effective empty.
	onlyempty := s.Trace("onlyempty")
	assert.Equal(t, LayerFile, onlyempty.Effective)
	assert.Equal(t, PresenceEmpty, onlyempty.EffectivePresence)

	// Empty -> set counts as a change even though both are "falsy".
	after := NewSnapshot(
		map[string]any{"onlyempty": "default-empty"},
		map[string]any{"onlyempty": "x"},
		map[string]any{},
		map[string]any{},
	)
	report := s.Diff(after)
	c := findChange(t, report, "onlyempty")
	assert.True(t, c.Changed)
	assert.Equal(t, PresenceEmpty, c.Before.Presence)
	assert.Equal(t, PresenceSet, c.After.Presence)
}

// TestEmptyEnvFallsBackUnlessAllowed mirrors AllowEmptyEnv semantics.
func TestEmptyEnvFallsBackUnlessAllowed(t *testing.T) {
	dropped := NewSnapshot(
		map[string]any{},
		map[string]any{"k": "file"},
		map[string]any{"k": ""},
		map[string]any{},
	)
	tr := dropped.Trace("k")
	assert.Equal(t, LayerFile, tr.Effective)

	allowed := NewSnapshot(
		map[string]any{},
		map[string]any{"k": "file"},
		map[string]any{"k": ""},
		map[string]any{},
		SnapshotAllowEmptyEnv(true),
	)
	tr = allowed.Trace("k")
	assert.Equal(t, LayerEnv, tr.Effective)
	assert.Equal(t, PresenceEmpty, tr.EffectivePresence)
}

// TestSnapshotAliasesCaseInsensitive covers case normalization and alias
// resolution, matching actual Viper reads.
func TestSnapshotAliasesCaseInsensitive(t *testing.T) {
	s := NewSnapshot(
		map[string]any{},
		map[string]any{"UserName": "alice", "Db": map[string]any{"Host": "localhost"}},
		map[string]any{},
		map[string]any{},
		SnapshotAliases(map[string]string{"user": "username", "database": "db.host"}),
	)

	// Map keys are normalized to lower case and lookups are case-insensitive.
	tr := s.Trace("USERNAME")
	assert.Equal(t, LayerFile, tr.Effective)
	assert.Equal(t, "alice", tr.EffectiveValue)
	assert.Equal(t, "username", tr.Key)

	// Simple alias resolves to the canonical key.
	tr = s.Trace("User")
	assert.Equal(t, "username", tr.Key)
	assert.Equal(t, "alice", tr.EffectiveValue)

	// Nested alias resolves path-wise.
	tr = s.Trace("DATABASE")
	assert.Equal(t, "db.host", tr.Key)
	assert.Equal(t, "localhost", tr.EffectiveValue)

	// Canonical keys are enumerated, alias names are not duplicated.
	var keys []string
	keys = s.Keys()
	assert.Contains(t, keys, "username")
	assert.Contains(t, keys, "db.host")
	for _, k := range keys {
		assert.NotEqual(t, "user", k)
		assert.NotEqual(t, "database", k)
		assert.Equal(t, strings.ToLower(k), k)
	}
}

// TestNestedOverride verifies nested map merge and parent shadowing.
func TestNestedOverride(t *testing.T) {
	s := NewSnapshot(
		map[string]any{},
		map[string]any{
			"server": map[string]any{
				"host": "file-host",
				"port": 1,
			},
		},
		map[string]any{},
		map[string]any{
			"server": map[string]any{
				"port": 2,
			},
		},
	)

	// Deep merge: overridden leaf comes from override, untouched leaf from file.
	host := s.Trace("server.host")
	assert.Equal(t, LayerFile, host.Effective)
	assert.Equal(t, "file-host", host.EffectiveValue)

	port := s.Trace("server.port")
	assert.Equal(t, LayerOverride, port.Effective)
	assert.Equal(t, 2, port.EffectiveValue)
	assert.Equal(t, PresenceSet, port.Layers[LayerFile].Presence)
	assert.Equal(t, 1, port.Layers[LayerFile].Value)

	// A scalar parent shadows descendants in lower-priority layers, mirroring
	// Viper.Get: the override scalar wins and the default leaf is unreachable.
	shadowed := NewSnapshot(
		map[string]any{"server": map[string]any{"host": "default-host"}},
		map[string]any{},
		map[string]any{},
		map[string]any{"server": "scalar"},
	)
	tr := shadowed.Trace("server")
	assert.Equal(t, LayerOverride, tr.Effective)
	assert.Equal(t, "scalar", tr.EffectiveValue)
	assert.Equal(t, PresenceSet, tr.Layers[LayerDefault].Presence)
	assert.Equal(t, map[string]any{"host": "default-host"}, tr.Layers[LayerDefault].Value)
	leaf := shadowed.Trace("server.host")
	assert.Equal(t, PresenceMissing, leaf.EffectivePresence)
	assert.Equal(t, Layer(""), leaf.Effective)
	assert.Nil(t, leaf.EffectiveValue)

	// The effective resolution must match a real Viper for the same inputs.
	vv := New()
	vv.SetDefault("server.host", "default-host")
	vv.Set("server", "scalar")
	assert.Nil(t, vv.Get("server.host"))
	assert.Equal(t, "scalar", vv.Get("server"))

	// Diff of a nested override reports the per-leaf transition.
	after := NewSnapshot(
		map[string]any{},
		map[string]any{"server": map[string]any{"host": "file-host", "port": 1}},
		map[string]any{},
		map[string]any{"server": map[string]any{"port": 3}},
	)
	report := s.Diff(after)
	c := findChange(t, report, "server.port")
	assert.True(t, c.Changed)
	assert.Equal(t, 2, c.Before.Value)
	assert.Equal(t, 3, c.After.Value)
	assert.Equal(t, LayerOverride, c.Before.Layer)
}

// TestSnapshotInputsAreNotMutated proves snapshots own their data and diffing
// identical snapshots reports no change.
func TestSnapshotInputsAreNotMutated(t *testing.T) {
	defaults := map[string]any{"a": map[string]any{"b": 1}, "Up": 2}
	file := map[string]any{"a": map[string]any{"c": 3}}
	env := map[string]any{"EMPTY": ""}
	override := map[string]any{"x": "y"}

	s := NewSnapshot(defaults, file, env, override)

	// Mutating the inputs after construction must not affect the snapshot.
	defaults["a"].(map[string]any)["b"] = 999
	defaults["new"] = true
	delete(file["a"].(map[string]any), "c")
	file["a"].(map[string]any)["injected"] = true

	tr := s.Trace("a.b")
	assert.Equal(t, LayerDefault, tr.Effective)
	assert.Equal(t, 1, tr.EffectiveValue)
	assert.Equal(t, PresenceSet, s.Trace("a.c").EffectivePresence)
	effectiveMap, ok := s.Trace("a").EffectiveValue.(map[string]any)
	require.True(t, ok)
	_, hasInjected := effectiveMap["injected"]
	assert.False(t, hasInjected)
	assert.Equal(t, PresenceMissing, s.Trace("new").EffectivePresence)

	// Upper-case input key was normalized.
	assert.Equal(t, PresenceSet, s.Trace("up").EffectivePresence)

	// Empty env string was dropped by default.
	assert.Equal(t, PresenceMissing, s.Trace("empty").Layers[LayerEnv].Presence)

	// Identical snapshots diff to "no changes" and share no structure.
	s2 := NewSnapshot(
		map[string]any{"a": map[string]any{"b": 1}, "up": 2},
		map[string]any{"a": map[string]any{"c": 3}},
		map[string]any{},
		map[string]any{"x": "y"},
	)
	report := s.Diff(s2)
	assert.Empty(t, report.Changed())
	for _, c := range report.Changes {
		assert.False(t, c.Changed, "key %s unexpectedly changed", c.Key)
	}
}

// TestLayerSnapshotDoesNotRereadEnv takes a snapshot from a live Viper, then
// changes the process environment and verifies Trace/Diff use the frozen
// capture instead of re-reading the environment.
func TestLayerSnapshotDoesNotRereadEnv(t *testing.T) {
	v := New()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetDefault("port", 1)
	t.Setenv("PORT", "2")
	v.BindEnv("port")
	v.AutomaticEnv()

	snap := v.LayerSnapshot()

	// Snapshot captured the env value at capture time.
	tr := snap.Trace("port")
	require.Equal(t, LayerEnv, tr.Effective)
	assert.Equal(t, "2", tr.EffectiveValue)

	// Change the environment after the snapshot. The snapshot must not move.
	t.Setenv("PORT", "3")
	tr = snap.Trace("port")
	assert.Equal(t, LayerEnv, tr.Effective)
	assert.Equal(t, "2", tr.EffectiveValue)
}

// TestLayerSnapshotFileToEnv is the end-to-end acceptance scenario on a real
// Viper: file sets the key to 1 first, environment overrides it to 2 later.
func TestLayerSnapshotFileToEnv(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("port: 1\npassword: filepw\n")))

	before := v.LayerSnapshot()

	v.AutomaticEnv()
	t.Setenv("PORT", "2")
	t.Setenv("PASSWORD", "envpw")

	after := v.LayerSnapshot()
	report := before.Diff(after)

	c := findChange(t, report, "port")
	assert.True(t, c.Changed)
	assert.Equal(t, LayerFile, c.Before.Layer)
	assert.Equal(t, 1, c.Before.Value)
	assert.Equal(t, LayerEnv, c.After.Layer)
	assert.Equal(t, "2", c.After.Value)

	pw := findChange(t, report, "password")
	assert.True(t, pw.Changed)
	assert.True(t, pw.Sensitive)
	assert.Equal(t, PresenceRedacted, pw.Before.Presence)
	assert.Equal(t, PresenceRedacted, pw.After.Presence)
	assert.Nil(t, pw.Before.Value)
	assert.Nil(t, pw.After.Value)

	rendered := report.String()
	assert.NotContains(t, rendered, "filepw")
	assert.NotContains(t, rendered, "envpw")
	assert.Contains(t, rendered, "password: file(redacted) -> env(redacted)")
}

// TestTraceStringDiagnostic documents the single-key diagnostic format.
func TestTraceStringDiagnostic(t *testing.T) {
	s := NewSnapshot(
		map[string]any{},
		map[string]any{"port": 1},
		map[string]any{"port": "2"},
		map[string]any{},
	)
	line := s.Trace("port").TraceString()
	assert.Contains(t, line, "port: set=\"2\"")
	assert.Contains(t, line, "[effective: env;")
	assert.Contains(t, line, "file(set=1)")
	assert.Contains(t, line, "env(set=\"2\")")
	assert.Contains(t, line, "default(missing)")
	assert.Contains(t, line, "override(missing)")
}

// TestNestedSensitiveKeyAndBoundEnv covers nested sensitive paths and bound
// environment variables on a live Viper instance.
func TestNestedSensitiveKeyAndBoundEnv(t *testing.T) {
	v := New()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("db:\n  password: filepw\n  user: admin\n")))
	v.BindEnv("db.password")
	before := v.LayerSnapshot()

	t.Setenv("DB_PASSWORD", "envpw")
	after := v.LayerSnapshot()

	report := before.Diff(after)
	c := findChange(t, report, "db.password")
	assert.True(t, c.Changed)
	assert.True(t, c.Sensitive)
	assert.Equal(t, LayerFile, c.Before.Layer)
	assert.Equal(t, LayerEnv, c.After.Layer)
	assert.Equal(t, PresenceRedacted, c.Before.Presence)
	assert.Nil(t, c.Before.Value)
	assert.Nil(t, c.After.Value)

	rendered := report.String()
	assert.NotContains(t, rendered, "filepw")
	assert.NotContains(t, rendered, "envpw")

	// Non-sensitive nested key still shows values.
	user := findChange(t, report, "db.user")
	assert.False(t, user.Changed)
	assert.Equal(t, "admin", user.After.Value)

	// Custom matcher is supported.
	custom := before.Diff(after, DiffSensitiveMatcher(func(k string) bool {
		return k == "db.user"
	}))
	cu := findChange(t, custom, "db.user")
	assert.True(t, cu.Sensitive)
	assert.Nil(t, cu.After.Value)
}

// TestMissingToMissingIsUnchanged ensures absent keys do not produce noise.
func TestMissingToMissingIsUnchanged(t *testing.T) {
	a := NewSnapshot(nil, map[string]any{"a": 1}, nil, nil)
	b := NewSnapshot(nil, map[string]any{"a": 1}, nil, nil)
	r := a.Diff(b)
	assert.Empty(t, r.Changed())

	// A new key appearing only in the second snapshot is reported as missing
	// -> set with the source layer.
	c := NewSnapshot(nil, map[string]any{"a": 1, "b": 2}, nil, nil)
	r = a.Diff(c)
	ch := findChange(t, r, "b")
	assert.True(t, ch.Changed)
	assert.Equal(t, PresenceMissing, ch.Before.Presence)
	assert.Equal(t, LayerFile, ch.After.Layer)
	assert.Equal(t, 2, ch.After.Value)
	assert.Contains(t, r.String(), "b: missing -> file(set=2)")
}
