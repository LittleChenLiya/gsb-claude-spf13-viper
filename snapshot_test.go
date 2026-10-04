// Copyright © 2014 Steve Francia <spf@spf13.com>.
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

// TestSnapshotDiffFileToEnv covers the primary acceptance scenario: a key is
// first set by the file layer to 1, then the env layer sets it to 2. The diff
// must report the source change (file -> env) and the effective value change.
func TestSnapshotDiffFileToEnv(t *testing.T) {
	before := NewSnapshot()
	before.RecordLayer(LayerFile, map[string]any{"port": 1})

	after := NewSnapshot()
	after.RecordLayer(LayerFile, map[string]any{"port": 1})
	after.RecordLayer(LayerEnv, map[string]any{"port": 2})

	changes := before.Diff(after)
	require.Len(t, changes, 1)

	c := changes[0]
	assert.Equal(t, "port", c.Key)
	assert.False(t, c.Sensitive)

	// Old effective value: file=1.
	assert.True(t, c.Old.Present)
	assert.Equal(t, LayerFile, c.Old.Layer)
	assert.Equal(t, 1, c.Old.Value)

	// New effective value: env=2 (env wins over file).
	assert.True(t, c.New.Present)
	assert.Equal(t, LayerEnv, c.New.Layer)
	assert.Equal(t, 2, c.New.Value)

	// Diagnostic format: source and value change.
	assert.Equal(t, "port: 1 -> 2 (source: file -> env)", c.String())
}

// TestSnapshotDiffSensitive covers the sensitive-key acceptance scenario: a
// sensitive key (password) must only report the change and the source layers,
// never the values.
func TestSnapshotDiffSensitive(t *testing.T) {
	before := NewSnapshot(WithSensitiveKeys("password"))
	before.RecordLayer(LayerFile, map[string]any{"password": "secret1"})

	after := NewSnapshot(WithSensitiveKeys("password"))
	after.RecordLayer(LayerFile, map[string]any{"password": "secret1"})
	after.RecordLayer(LayerEnv, map[string]any{"password": "secret2"})

	changes := before.Diff(after)
	require.Len(t, changes, 1)

	c := changes[0]
	assert.Equal(t, "password", c.Key)
	assert.True(t, c.Sensitive)

	// Values must not be exported.
	assert.Nil(t, c.Old.Value)
	assert.Nil(t, c.New.Value)

	// Only the change and the source layers are reported.
	assert.Equal(t, "password: changed (source: file -> env)", c.String())

	// Ensure the raw values never leak into the diagnostic.
	diag := c.String()
	assert.NotContains(t, diag, "secret1")
	assert.NotContains(t, diag, "secret2")
}

// TestSnapshotDistinguishesNullFromMissing covers the acceptance requirement
// that null values must not be mistaken for missing keys.
func TestSnapshotDistinguishesNullFromMissing(t *testing.T) {
	// Key set to null in the file layer.
	withNull := NewSnapshot()
	withNull.RecordLayer(LayerFile, map[string]any{"feature": nil})

	// Key absent entirely.
	without := NewSnapshot()

	// Effective value of the null-set key.
	v := withNull.Effective("feature")
	assert.True(t, v.Present, "a key set to null must be reported as present")
	assert.Nil(t, v.Value)
	assert.Equal(t, LayerFile, v.Layer)
	assert.Equal(t, "<nil>", v.String())

	// Effective value of the missing key.
	missing := without.Effective("feature")
	assert.False(t, missing.Present, "a key absent from every layer must be reported as missing")
	assert.Equal(t, "<missing>", missing.String())

	// The diff between null-set and missing must be a real change.
	changes := withNull.Diff(without)
	require.Len(t, changes, 1)
	assert.Equal(t, "feature", changes[0].Key)
	assert.True(t, changes[0].Old.Present)
	assert.False(t, changes[0].New.Present)
	assert.Equal(t, "feature: <nil> -> <missing> (source: file -> <missing>)", changes[0].String())
}

// TestSnapshotEmptyStringNotMissing covers the acceptance requirement that an
// empty string value must not be mistaken for a missing key.
func TestSnapshotEmptyStringNotMissing(t *testing.T) {
	s := NewSnapshot()
	s.RecordLayer(LayerFile, map[string]any{"greeting": ""})

	v := s.Effective("greeting")
	assert.True(t, v.Present, "a key set to empty string must be reported as present")
	assert.Equal(t, "", v.Value)
	assert.Equal(t, LayerFile, v.Layer)
	assert.Equal(t, "", v.String())
}

// TestSnapshotCaseAlias covers the case-alias acceptance requirement: keys
// differing only in case must be treated as the same key, and aliases must be
// resolved.
func TestSnapshotCaseAlias(t *testing.T) {
	// Case-insensitivity: "Foo" and "foo" are the same key.
	s := NewSnapshot()
	s.RecordLayer(LayerFile, map[string]any{"Foo": 1})

	assert.Equal(t, 1, s.Effective("foo").Value)
	assert.Equal(t, 1, s.Effective("FOO").Value)
	assert.Equal(t, 1, s.Effective("Foo").Value)

	// Alias resolution: "svc" is an alias for "service.name".
	aliased := NewSnapshot(WithAliases(map[string]string{"svc": "service.name"}))
	aliased.RecordLayer(LayerFile, map[string]any{"service": map[string]any{"name": "api"}})

	v := aliased.Effective("svc")
	assert.True(t, v.Present)
	assert.Equal(t, "api", v.Value)
	assert.Equal(t, LayerFile, v.Layer)
}

// TestSnapshotNestedOverride covers the nested-override acceptance requirement:
// nested keys must be resolved through the path, and a higher-precedence layer
// overrides a nested value from a lower layer.
func TestSnapshotNestedOverride(t *testing.T) {
	before := NewSnapshot()
	before.RecordLayer(LayerFile, map[string]any{
		"database": map[string]any{
			"host": "localhost",
			"port": 5432,
		},
	})

	after := NewSnapshot()
	after.RecordLayer(LayerFile, map[string]any{
		"database": map[string]any{
			"host": "localhost",
			"port": 5432,
		},
	})
	after.RecordLayer(LayerOverride, map[string]any{
		"database": map[string]any{
			"port": 6543,
		},
	})

	changes := before.Diff(after)
	require.Len(t, changes, 1)

	c := changes[0]
	assert.Equal(t, "database.port", c.Key)
	assert.Equal(t, 5432, c.Old.Value)
	assert.Equal(t, 6543, c.New.Value)
	assert.Equal(t, LayerFile, c.Old.Layer)
	assert.Equal(t, LayerOverride, c.New.Layer)
	assert.Equal(t, "database.port: 5432 -> 6543 (source: file -> override)", c.String())
}

// TestSnapshotInputImmutability covers the input-immutability acceptance
// requirement: mutating the caller's map after RecordLayer must not affect the
// snapshot.
func TestSnapshotInputImmutability(t *testing.T) {
	values := map[string]any{
		"port": 8080,
		"database": map[string]any{
			"host": "localhost",
		},
		"tags": []any{"a", "b"},
	}

	s := NewSnapshot()
	s.RecordLayer(LayerFile, values)

	// Mutate the caller's map after recording.
	values["port"] = 9090
	values["database"].(map[string]any)["host"] = "remote"
	values["tags"].([]any)[0] = "z"
	values["newkey"] = "added"

	// The snapshot must retain the original values.
	assert.Equal(t, 8080, s.Effective("port").Value)
	assert.Equal(t, "localhost", s.Effective("database.host").Value)
	assert.Equal(t, "a", s.Effective("tags").Value.([]any)[0])
	assert.False(t, s.Effective("newkey").Present)
}

// TestSnapshotEnvFlattening covers the env-layer flattening: nested env values
// are flattened to dotted keys, and flat dotted keys are preserved.
func TestSnapshotEnvFlattening(t *testing.T) {
	s := NewSnapshot()
	s.RecordLayer(LayerEnv, map[string]any{
		"database": map[string]any{"host": "envhost"},
		"port":     "9090",
	})

	assert.Equal(t, "envhost", s.Effective("database.host").Value)
	assert.Equal(t, "9090", s.Effective("port").Value)
}

// TestSnapshotPrecedence covers the full precedence chain: override > env >
// file > default.
func TestSnapshotPrecedence(t *testing.T) {
	s := NewSnapshot()
	s.RecordLayer(LayerDefault, map[string]any{"k": "default"})
	s.RecordLayer(LayerFile, map[string]any{"k": "file"})
	s.RecordLayer(LayerEnv, map[string]any{"k": "env"})
	s.RecordLayer(LayerOverride, map[string]any{"k": "override"})

	v := s.Effective("k")
	assert.Equal(t, LayerOverride, v.Layer)
	assert.Equal(t, "override", v.Value)

	// Without override, env wins.
	s2 := NewSnapshot()
	s2.RecordLayer(LayerDefault, map[string]any{"k": "default"})
	s2.RecordLayer(LayerFile, map[string]any{"k": "file"})
	s2.RecordLayer(LayerEnv, map[string]any{"k": "env"})
	assert.Equal(t, "env", s2.Effective("k").Value)

	// Without env, file wins.
	s3 := NewSnapshot()
	s3.RecordLayer(LayerDefault, map[string]any{"k": "default"})
	s3.RecordLayer(LayerFile, map[string]any{"k": "file"})
	assert.Equal(t, "file", s3.Effective("k").Value)

	// Without file, default wins.
	s4 := NewSnapshot()
	s4.RecordLayer(LayerDefault, map[string]any{"k": "default"})
	assert.Equal(t, "default", s4.Effective("k").Value)
}

// TestSnapshotNoChangeWhenEqual covers the case where two snapshots have
// identical effective values: no changes are reported.
func TestSnapshotNoChangeWhenEqual(t *testing.T) {
	s1 := NewSnapshot()
	s1.RecordLayer(LayerFile, map[string]any{"port": 8080})

	s2 := NewSnapshot()
	s2.RecordLayer(LayerFile, map[string]any{"port": 8080})

	assert.Empty(t, s1.Diff(s2))
}

// TestSnapshotDiffIsPure covers the requirement that the diff operation does
// not re-read the environment or trigger config watchers. Since the snapshot
// holds only the submitted values, a diff between two snapshots with the same
// submitted values yields no changes, even if the process environment has
// changed.
func TestSnapshotDiffIsPure(t *testing.T) {
	t.Setenv("SNAPSHOT_TEST_PORT", "1")

	s1 := NewSnapshot()
	s1.RecordLayer(LayerEnv, map[string]any{"port": "1"})

	// Change the process environment after recording.
	t.Setenv("SNAPSHOT_TEST_PORT", "2")

	s2 := NewSnapshot()
	s2.RecordLayer(LayerEnv, map[string]any{"port": "1"})

	// The diff must be based on the submitted snapshots, not the live env.
	assert.Empty(t, s1.Diff(s2))
}

// TestSnapshotCustomKeyDelim covers the WithKeyDelim option.
func TestSnapshotCustomKeyDelim(t *testing.T) {
	s := NewSnapshot(WithKeyDelim("::"))
	s.RecordLayer(LayerFile, map[string]any{"a": map[string]any{"b": 1}})

	assert.Equal(t, 1, s.Effective("a::b").Value)
	assert.False(t, s.Effective("a.b").Present)
}

// TestSnapshotDiffDeterministic covers the requirement that changes are sorted
// by key for deterministic output.
func TestSnapshotDiffDeterministic(t *testing.T) {
	before := NewSnapshot()
	before.RecordLayer(LayerFile, map[string]any{
		"zebra": 1,
		"alpha": 2,
		"mango": 3,
	})

	after := NewSnapshot()
	after.RecordLayer(LayerEnv, map[string]any{
		"zebra": 10,
		"alpha": 20,
		"mango": 30,
	})

	changes := before.Diff(after)
	require.Len(t, changes, 3)
	assert.Equal(t, "alpha", changes[0].Key)
	assert.Equal(t, "mango", changes[1].Key)
	assert.Equal(t, "zebra", changes[2].Key)

	// All diagnostics are well-formed and contain no raw env re-reads.
	for _, c := range changes {
		assert.True(t, strings.HasSuffix(c.String(), "(source: file -> env)"))
	}
}

// TestSnapshotConsistentWithViper verifies that the snapshot's Effective
// matches Viper's actual Get for the same layer data. This ensures key
// normalization and nested path handling are consistent with actual reads.
func TestSnapshotConsistentWithViper(t *testing.T) {
	v := New()
	v.SetDefault("defaultkey", "def")
	v.SetDefault("nested.key", "def-nested")
	v.Set("overridekey", "ov")
	v.Set("nested.override", "ov-nested")

	config := map[string]any{
		"filekey": "file",
		"nested": map[string]any{
			"file": "file-nested",
		},
	}
	require.NoError(t, v.MergeConfigMap(config))

	// Env: bind a key and set the env var.
	t.Setenv("VIPER_ENVBIND", "envval")
	require.NoError(t, v.BindEnv("envbind"))

	// Build a snapshot from the same layer data.
	s := NewSnapshot()
	s.RecordLayer(LayerDefault, v.defaults)
	s.RecordLayer(LayerFile, v.config)
	s.RecordLayer(LayerOverride, v.override)

	// Resolve env values the same way Viper does.
	envValues := map[string]any{}
	for key := range v.env {
		for _, envkey := range v.env[key] {
			if val, ok := v.getEnv(envkey); ok {
				envValues[key] = val
			}
		}
	}
	s.RecordLayer(LayerEnv, envValues)

	// Compare Effective vs Get for every key Viper knows about.
	for _, key := range v.AllKeys() {
		vVal := v.Get(key)
		sVal := s.Effective(key)
		assert.Equal(t, vVal, sVal.Value, "key: %s", key)
	}
}
