// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const usageConfigYAML = `
db:
  host: localhost
  port: 5432
  potr: 5433
`

func newTrackedViper(t *testing.T, config string) *Viper {
	t.Helper()

	v := NewWithOptions(WithUsageTracking())
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(config)))

	assert.True(t, v.UsageTrackingEnabled())

	return v
}

func TestUsageTrackingReportsOnlyUnreadConfigKeys(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	assert.Equal(t, "localhost", v.GetString("db.host"))
	assert.Equal(t, 5432, v.GetInt("db.port"))

	assert.Equal(t, []string{"db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingIsCaseInsensitive(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	assert.Equal(t, "localhost", v.GetString("DB.Host"))
	assert.Equal(t, 5433, v.GetInt("DB.POTR"))

	assert.Equal(t, []string{"db.port"}, v.UnusedKeys())
}

func TestUsageTrackingResolvesAliases(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)
	v.RegisterAlias("database.host", "db.host")

	assert.Equal(t, "localhost", v.GetString("database.host"))
	assert.Equal(t, 5432, v.GetInt("db.port"))

	assert.Equal(t, []string{"db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingSubViper(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	sub := v.Sub("db")
	require.NotNil(t, sub)
	assert.True(t, sub.UsageTrackingEnabled())

	// Creating the Sub Viper does not consume the parent subtree.
	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, v.UnusedKeys())

	assert.Equal(t, "localhost", sub.GetString("host"))
	assert.Equal(t, 5432, sub.GetInt("port"))

	assert.Equal(t, []string{"potr"}, sub.UnusedKeys())
	assert.Equal(t, []string{"db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingNestedUnmarshal(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	type dbConfig struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	}

	var db dbConfig
	require.NoError(t, v.UnmarshalKey("db", &db))
	assert.Equal(t, "localhost", db.Host)
	assert.Equal(t, 5432, db.Port)

	assert.Equal(t, []string{"db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingRootUnmarshalOnlyConsumesStructFields(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	type config struct {
		DB struct {
			Host string `mapstructure:"host"`
			Port int    `mapstructure:"port"`
		} `mapstructure:"db"`
	}

	var cfg config
	require.NoError(t, v.Unmarshal(&cfg))
	assert.Equal(t, "localhost", cfg.DB.Host)
	assert.Equal(t, 5432, cfg.DB.Port)

	assert.Equal(t, []string{"db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingParentMapConsumesSubtree(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	db := v.GetStringMap("db")
	assert.Len(t, db, 3)

	assert.Empty(t, v.UnusedKeys())
}

func TestUsageTrackingMapUnmarshalConsumesSubtree(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	db := map[string]any{}
	require.NoError(t, v.UnmarshalKey("db", &db))
	assert.Len(t, db, 3)

	assert.Empty(t, v.UnusedKeys())
}

func TestUsageTrackingDiagnosticsDoNotConsumeKeys(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	assert.True(t, v.IsSet("db.host"))
	assert.Contains(t, v.AllKeys(), "db.host")
	assert.Equal(t, "localhost", v.AllSettings()["db"].(map[string]any)["host"])
	assert.True(t, v.InConfig("db.host"))
	assert.NotPanics(t, func() { v.DebugTo(&bytes.Buffer{}) })

	expected := []string{"db.host", "db.port", "db.potr"}
	assert.Equal(t, expected, v.UnusedKeys())
	// Repeated diagnostics calls are stable and do not self-consume keys.
	assert.Equal(t, expected, v.UnusedKeys())
}

func TestUsageTrackingReset(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	assert.Equal(t, "localhost", v.GetString("db.host"))
	assert.Equal(t, []string{"db.port", "db.potr"}, v.UnusedKeys())

	v.ResetUsage()
	assert.True(t, v.UsageTrackingEnabled())
	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, v.UnusedKeys())

	v.DisableUsageTracking()
	assert.False(t, v.UsageTrackingEnabled())
	assert.Nil(t, v.UnusedKeys())

	v.EnableUsageTracking()
	assert.True(t, v.UsageTrackingEnabled())
	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingSortedStable(t *testing.T) {
	config := `
zebra: 1
apple:
  zebra: 2
  apple: 3
middle: 4
`
	v := newTrackedViper(t, config)

	expected := []string{"apple.apple", "apple.zebra", "middle", "zebra"}
	for range 5 {
		assert.Equal(t, expected, v.UnusedKeys())
	}
}

func TestUsageTrackingDisabledByDefault(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(usageConfigYAML)))

	assert.False(t, v.UsageTrackingEnabled())
	assert.Nil(t, v.UnusedKeys())

	assert.Equal(t, "localhost", v.GetString("db.host"))
	assert.Nil(t, v.UnusedKeys())
}

func TestUsageTrackingReadsBeforeEnableAreNotRecorded(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(usageConfigYAML)))

	assert.Equal(t, "localhost", v.GetString("db.host"))

	v.EnableUsageTracking()
	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingConfigReloadPicksUpCurrentKeys(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	assert.Equal(t, "localhost", v.GetString("db.host"))

	require.NoError(t, v.ReadConfig(bytes.NewBufferString("only: true")))
	assert.Equal(t, []string{"only"}, v.UnusedKeys())
}

func TestUsageTrackingNestedSubViper(t *testing.T) {
	config := `
server:
  db:
    host: localhost
    port: 5432
    potr: 5433
`
	v := newTrackedViper(t, config)

	server := v.Sub("server")
	db := server.Sub("db")
	require.NotNil(t, db)

	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, server.UnusedKeys())

	assert.Equal(t, "localhost", db.GetString("host"))
	assert.Equal(t, 5432, db.GetInt("port"))

	assert.Equal(t, []string{"potr"}, db.UnusedKeys())
	assert.Equal(t, []string{"db.potr"}, server.UnusedKeys())
	assert.Equal(t, []string{"server.db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingGlobalFunctions(t *testing.T) {
	defer Reset()

	SetOptions(WithUsageTracking())
	SetConfigType("yaml")
	require.NoError(t, ReadConfig(bytes.NewBufferString(usageConfigYAML)))

	assert.Equal(t, "localhost", GetString("db.host"))
	assert.Equal(t, []string{"db.port", "db.potr"}, UnusedKeys())

	ResetUsage()
	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, UnusedKeys())

	DisableUsageTracking()
	assert.Nil(t, UnusedKeys())
}

func TestUsageTrackingUnmarshalStructWithMapField(t *testing.T) {
	config := `
service:
  name: api
  labels:
    team: core
    tier: backend
  bogus: true
`
	v := newTrackedViper(t, config)

	type serviceConfig struct {
		Name   string            `mapstructure:"name"`
		Labels map[string]string `mapstructure:"labels"`
	}
	type cfg struct {
		Service serviceConfig `mapstructure:"service"`
	}

	var out cfg
	require.NoError(t, v.Unmarshal(&out))
	assert.Equal(t, "api", out.Service.Name)
	assert.Equal(t, map[string]string{"team": "core", "tier": "backend"}, out.Service.Labels)

	assert.Equal(t, []string{"service.bogus"}, v.UnusedKeys())
}

func TestUsageTrackingCustomDelimiter(t *testing.T) {
	v := NewWithOptions(WithUsageTracking(), KeyDelimiter("/"))
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString("db:\n  host: localhost\n  potr: 5433\n")))

	assert.Equal(t, "localhost", v.GetString("db/host"))
	assert.Equal(t, []string{"db/potr"}, v.UnusedKeys())
}

func TestUsageTrackingGetMissingKeyDoesNotConsumeKeys(t *testing.T) {
	v := newTrackedViper(t, usageConfigYAML)

	assert.Nil(t, v.Get("db.missing"))
	assert.Nil(t, v.Sub("does.not.exist"))

	assert.Equal(t, []string{"db.host", "db.port", "db.potr"}, v.UnusedKeys())
}
