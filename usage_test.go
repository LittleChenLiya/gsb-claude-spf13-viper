package viper

import (
	"bytes"
	"sort"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mapstructureMetadataHolder struct {
	metadata *mapstructure.Metadata
}

func withTestMetadata(h *mapstructureMetadataHolder) DecoderConfigOption {
	h.metadata = &mapstructure.Metadata{}
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = h.metadata
	}
}

func newTrackedViper(t *testing.T, yamlConfig string, opts ...Option) *Viper {
	t.Helper()

	allOpts := append([]Option{TrackUsage()}, opts...)
	v := NewWithOptions(allOpts...)
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(yamlConfig)))
	return v
}

func TestUsageTrackingTypedGetLeavesOnlyTypo(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"  potr: 5432\n")

	assert.Equal(t, "localhost", v.GetString("db.host"))
	assert.Equal(t, 5432, v.GetInt("db.port"))

	assert.Equal(t, []string{"db.potr"}, v.UnusedKeys())
}

func TestUsageTrackingGet(t *testing.T) {
	v := newTrackedViper(t, ""+
		"read: yes\n"+
		"unread: no\n")

	assert.Equal(t, "yes", v.Get("read"))
	assert.Equal(t, []string{"unread"}, v.UnusedKeys())
}

func TestUsageTrackingAlias(t *testing.T) {
	v := newTrackedViper(t, ""+
		"host: localhost\n"+
		"port: 5432\n"+
		"unused: true\n")
	v.RegisterAlias("hostname", "host")

	assert.Equal(t, "localhost", v.GetString("HostName"))
	assert.Equal(t, 5432, v.GetInt("port"))

	assert.Equal(t, []string{"unused"}, v.UnusedKeys())
}

func TestUsageTrackingCaseInsensitive(t *testing.T) {
	v := newTrackedViper(t, ""+
		"DB:\n"+
		"  Host: localhost\n"+
		"  Port: 5432\n")

	assert.Equal(t, "localhost", v.GetString("DB.Host"))
	assert.Equal(t, 5432, v.GetInt("db.PORT"))

	assert.Empty(t, v.UnusedKeys())
}

func TestUsageTrackingSub(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"  potr: 5432\n"+
		"other:\n"+
		"  value: x\n")

	sub := v.Sub("DB")
	require.NotNil(t, sub)
	assert.Equal(t, "localhost", sub.GetString("host"))
	assert.Equal(t, 5432, sub.GetInt("port"))

	assert.Equal(t, []string{"db.potr", "other.value"}, v.UnusedKeys())
	assert.Equal(t, []string{"potr"}, sub.UnusedKeys())
}

func TestUsageTrackingSubAliased(t *testing.T) {
	v := newTrackedViper(t, ""+
		"database:\n"+
		"  host: localhost\n"+
		"  port: 5432\n")
	v.RegisterAlias("db", "database")

	sub := v.Sub("db")
	require.NotNil(t, sub)
	assert.Equal(t, "localhost", sub.GetString("host"))

	assert.Equal(t, []string{"database.port"}, v.UnusedKeys())
	assert.Equal(t, []string{"port"}, sub.UnusedKeys())
}

func TestUsageTrackingAliasRegisteredBeforeRead(t *testing.T) {
	v := NewWithOptions(TrackUsage())
	v.SetConfigType("yaml")
	v.RegisterAlias("host", "hostname")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(""+
		"hostname: localhost\n"+
		"port: 5432\n")))

	assert.Equal(t, "localhost", v.GetString("host"))
	assert.Equal(t, []string{"port"}, v.UnusedKeys())
}

func TestUsageTrackingCustomDelimiter(t *testing.T) {
	v := NewWithOptions(TrackUsage(), KeyDelimiter("/"))
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n")))

	assert.Equal(t, "localhost", v.GetString("db/host"))
	assert.Equal(t, []string{"db/port"}, v.UnusedKeys())
}

func TestUsageTrackingMergeConfig(t *testing.T) {
	v := newTrackedViper(t, "a: 1\n")
	assert.Equal(t, 1, v.GetInt("a"))

	require.NoError(t, v.MergeConfig(bytes.NewBufferString("b: 2\n")))
	assert.Equal(t, []string{"b"}, v.UnusedKeys())

	v.ResetUsage()
	assert.Equal(t, []string{"a", "b"}, v.UnusedKeys())
}

type usageDBConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type usageConfig struct {
	DB    usageDBConfig `mapstructure:"db"`
	Other string        `mapstructure:"other"`
}

type usageConfigWithMap struct {
	Name string            `mapstructure:"name"`
	DB   map[string]string `mapstructure:"db"`
}

func TestUsageTrackingUnmarshalStructWithMapField(t *testing.T) {
	v := newTrackedViper(t, ""+
		"name: app\n"+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"  potr: 5432\n"+
		"other: x\n")

	var cfg usageConfigWithMap
	require.NoError(t, v.Unmarshal(&cfg))
	assert.Equal(t, "app", cfg.Name)
	assert.Equal(t, "localhost", cfg.DB["host"])

	// The map field hands every leaf below db to the caller, so only the
	// top-level "other" key remains unused.
	assert.Equal(t, []string{"other"}, v.UnusedKeys())
}

func TestUsageTrackingUnmarshalIntoMap(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n")

	var m map[string]any
	require.NoError(t, v.Unmarshal(&m))
	assert.Empty(t, v.UnusedKeys())
}

func TestUsageTrackingUnmarshalKeyIntoMap(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"other: x\n")

	var m map[string]any
	require.NoError(t, v.UnmarshalKey("db", &m))
	assert.Equal(t, []string{"other"}, v.UnusedKeys())
}
func TestUsageTrackingNestedUnmarshal(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"  potr: 5432\n"+
		"other: hey\n")

	var db usageDBConfig
	require.NoError(t, v.UnmarshalKey("db", &db))
	assert.Equal(t, usageDBConfig{Host: "localhost", Port: 5432}, db)

	assert.Equal(t, []string{"db.potr", "other"}, v.UnusedKeys())
}

func TestUsageTrackingNestedUnmarshalConsumesMappedLeaves(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"other: hey\n")

	var db usageDBConfig
	require.NoError(t, v.UnmarshalKey("db", &db))

	assert.Equal(t, []string{"other"}, v.UnusedKeys())
}

func TestUsageTrackingFullUnmarshal(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"  potr: 5432\n"+
		"other: hey\n"+
		"extra: true\n")

	var cfg usageConfig
	require.NoError(t, v.Unmarshal(&cfg))
	assert.Equal(t, "localhost", cfg.DB.Host)
	assert.Equal(t, 5432, cfg.DB.Port)
	assert.Equal(t, "hey", cfg.Other)

	assert.Equal(t, []string{"db.potr", "extra"}, v.UnusedKeys())
}

func TestUsageTrackingUnmarshalExact(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"other: hey\n")

	var cfg usageConfig
	require.NoError(t, v.UnmarshalExact(&cfg))
	assert.Empty(t, v.UnusedKeys())
}

func TestUsageTrackingParentMap(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n"+
		"  potr: 5432\n"+
		"other:\n"+
		"  value: x\n")

	_ = v.GetStringMap("db")

	assert.Equal(t, []string{"other.value"}, v.UnusedKeys())
	assert.Equal(t, []string{"other.value"}, v.UnusedKeys())
}

func TestUsageTrackingDiagnosticsDoNotConsume(t *testing.T) {
	v := newTrackedViper(t, ""+
		"a: 1\n"+
		"b:\n"+
		"  c: 2\n"+
		"  d: 3\n")

	assert.True(t, v.IsSet("a"))
	assert.Contains(t, v.AllKeys(), "b.c")
	assert.Contains(t, v.AllSettings(), "a")
	assert.NotPanics(t, func() { v.DebugTo(&bytes.Buffer{}) })

	expected := []string{"a", "b.c", "b.d"}
	assert.Equal(t, expected, v.UnusedKeys())
	assert.Equal(t, expected, v.UnusedKeys())
}

func TestUsageTrackingStableSortedReport(t *testing.T) {
	v := newTrackedViper(t, ""+
		"zebra: 1\n"+
		"apple: 2\n"+
		"mango: 3\n"+
		"db:\n"+
		"  zeta: 4\n"+
		"  alpha: 5\n")

	report := v.UnusedKeys()
	assert.True(t, sort.StringsAreSorted(report))
	assert.Equal(t, []string{"apple", "db.alpha", "db.zeta", "mango", "zebra"}, report)
}

func TestUsageTrackingReset(t *testing.T) {
	v := newTrackedViper(t, ""+
		"a: 1\n"+
		"b: 2\n")

	assert.Equal(t, 1, v.GetInt("a"))
	assert.Equal(t, []string{"b"}, v.UnusedKeys())

	v.ResetUsage()
	assert.Equal(t, []string{"a", "b"}, v.UnusedKeys())

	assert.Equal(t, 2, v.GetInt("b"))
	assert.Equal(t, []string{"a"}, v.UnusedKeys())
}

func TestUsageTrackingDisabledByDefault(t *testing.T) {
	v := NewWithOptions()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString("a: 1\n")))

	assert.Nil(t, v.UnusedKeys())

	v.EnableUsageTracking()
	assert.Equal(t, 1, v.GetInt("a"))
	assert.Empty(t, v.UnusedKeys())
}

func TestUsageTrackingReadUnknownKey(t *testing.T) {
	v := newTrackedViper(t, "a: 1\n")

	assert.Nil(t, v.Get("missing"))
	assert.Equal(t, []string{"a"}, v.UnusedKeys())
}

func TestUsageTrackingUnmarshalPreservesUserMetadata(t *testing.T) {
	v := newTrackedViper(t, ""+
		"db:\n"+
		"  host: localhost\n"+
		"  port: 5432\n")

	userMetadata := &mapstructureMetadataHolder{}
	var db usageDBConfig
	require.NoError(t, v.UnmarshalKey("db", &db, withTestMetadata(userMetadata)))
	assert.Contains(t, userMetadata.metadata.Keys, "host")
	assert.Contains(t, userMetadata.metadata.Keys, "port")
}
