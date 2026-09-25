// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingFs counts how many times each file is opened for reading.
type countingFs struct {
	afero.Fs
	opens map[string]int
}

func newCountingFs(base afero.Fs) *countingFs {
	return &countingFs{Fs: base, opens: make(map[string]int)}
}

func (fs *countingFs) Open(name string) (afero.File, error) {
	fs.opens[name]++
	return fs.Fs.Open(name)
}

func writeTestFile(t *testing.T, fs afero.Fs, name, contents string) {
	t.Helper()
	require.NoError(t, afero.WriteFile(fs, name, []byte(contents), 0o644))
}

func includeTestViper(t *testing.T, fs afero.Fs, opts ...Option) *Viper {
	t.Helper()

	allOpts := append([]Option{ExperimentalInclude()}, opts...)
	v := NewWithOptions(allOpts...)
	v.SetFs(fs)
	v.SetConfigFile("/app/config.yaml")

	return v
}

func TestIncludeMergeOrderAndSharedReadOnce(t *testing.T) {
	t.Parallel()

	fs := newCountingFs(afero.NewMemMapFs())

	writeTestFile(t, fs, "/app/shared.yaml", "name: shared\nshared_only: yes\nnested:\n  from_shared: true\n  common: shared\n")
	writeTestFile(t, fs, "/app/a.yaml", "include: [shared.yaml]\nname: a\nfrom_a: true\nnested:\n  common: a\n")
	writeTestFile(t, fs, "/app/b.yaml", "include:\n  - shared.yaml\nname: b\nfrom_b: true\nnested:\n  common: b\n")
	writeTestFile(t, fs, "/app/config.yaml", "include:\n  - a.yaml\n  - b.yaml\nname: root\ntitle: root title\nnested:\n  root_key: true\n")

	v := includeTestViper(t, fs)
	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, "root", v.GetString("name"))
	assert.Equal(t, "root title", v.GetString("title"))
	assert.True(t, v.GetBool("from_a"))
	assert.True(t, v.GetBool("from_b"))
	assert.Equal(t, "yes", v.GetString("shared_only"))
	assert.True(t, v.GetBool("nested.from_shared"))
	assert.True(t, v.GetBool("nested.root_key"))

	// b is merged after a, so b's nested value wins.
	assert.Equal(t, "b", v.GetString("nested.common"))

	// The include directive itself is not part of the business config.
	assert.Nil(t, v.Get("include"))
	assert.NotContains(t, v.AllSettings(), "include")

	// shared is referenced by both a and b but is read only once.
	assert.Equal(t, 1, fs.opens[filepath.Clean("/app/shared.yaml")])
	assert.Equal(t, 1, fs.opens[filepath.Clean("/app/a.yaml")])
	assert.Equal(t, 1, fs.opens[filepath.Clean("/app/b.yaml")])
	assert.Equal(t, 1, fs.opens[filepath.Clean("/app/config.yaml")])
}

func TestIncludeSetAndEnvTakePrecedence(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/shared.yaml", "name: shared\nport: 1000\n")
	writeTestFile(t, fs, "/app/a.yaml", "include: [shared.yaml]\nname: a\nport: 2000\n")
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml]\nname: root\nport: 3000\n")

	v := includeTestViper(t, fs)
	v.Set("name", "set-value")
	v.AutomaticEnv()
	t.Setenv("PORT", "9090")

	require.NoError(t, v.ReadInConfig())

	// Set overrides have the highest priority.
	assert.Equal(t, "set-value", v.GetString("name"))

	// Environment variables beat config file values.
	assert.Equal(t, 9090, v.GetInt("port"))
}

func TestIncludeKeepsOldConfigOnFailure(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml]\nold: value\n")
	writeTestFile(t, fs, "/app/a.yaml", "include: [missing.yaml]\nold: from-a\n")

	v := includeTestViper(t, fs)

	// Establish an old, fully loaded configuration first.
	writeTestFile(t, fs, "/app/ok.yaml", "old: value\nkeep: me\n")
	v.SetConfigFile("/app/ok.yaml")
	require.NoError(t, v.ReadInConfig())
	assert.Equal(t, "value", v.GetString("old"))
	assert.Equal(t, "me", v.GetString("keep"))

	// A failing load must not replace the previous configuration.
	v.SetConfigFile("/app/config.yaml")
	err := v.ReadInConfig()
	require.Error(t, err)
	assert.Equal(t, "value", v.GetString("old"))
	assert.Equal(t, "me", v.GetString("keep"))

	var includeErr IncludeError
	require.True(t, errors.As(err, &includeErr))
	assert.Equal(t, []string{
		filepath.Clean("/app/config.yaml"),
		filepath.Clean("/app/a.yaml"),
		filepath.Clean("/app/missing.yaml"),
	}, includeErr.Chain)
}

func TestIncludeCycleReportsFullChain(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml]\n")
	writeTestFile(t, fs, "/app/a.yaml", "include: [b.yaml]\n")
	writeTestFile(t, fs, "/app/b.yaml", "include: [a.yaml]\n")

	v := includeTestViper(t, fs)
	err := v.ReadInConfig()
	require.Error(t, err)

	var includeErr IncludeError
	require.True(t, errors.As(err, &includeErr))
	assert.Equal(t, []string{
		filepath.Clean("/app/config.yaml"),
		filepath.Clean("/app/a.yaml"),
		filepath.Clean("/app/b.yaml"),
		filepath.Clean("/app/a.yaml"),
	}, includeErr.Chain)

	var cycleErr IncludeCycleError
	assert.True(t, errors.As(err, &cycleErr))
	assert.Contains(t, err.Error(), "include cycle")
	assert.Contains(t, err.Error(),
		filepath.Clean("/app/config.yaml")+" -> "+filepath.Clean("/app/a.yaml")+" -> "+filepath.Clean("/app/b.yaml"))
}

func TestIncludeSiblingReferenceIsNotACycle(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/shared.yaml", "shared: yes\n")
	writeTestFile(t, fs, "/app/a.yaml", "include: [shared.yaml]\n")
	writeTestFile(t, fs, "/app/b.yaml", "include: [shared.yaml]\n")
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml, b.yaml]\n")

	v := includeTestViper(t, fs)
	require.NoError(t, v.ReadInConfig())
	assert.Equal(t, "yes", v.GetString("shared"))
}

func TestIncludeMissingFileReportsChain(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [dir/a.yaml]\n")
	writeTestFile(t, fs, "/app/dir/a.yaml", "include: [b.yaml]\n")

	v := includeTestViper(t, fs)
	err := v.ReadInConfig()
	require.Error(t, err)

	var includeErr IncludeError
	require.True(t, errors.As(err, &includeErr))
	assert.Equal(t, []string{
		filepath.Clean("/app/config.yaml"),
		filepath.Clean("/app/dir/a.yaml"),
		filepath.Clean("/app/dir/b.yaml"),
	}, includeErr.Chain)
	assert.Contains(t, err.Error(), filepath.Clean("/app/dir/b.yaml"))
}

func TestIncludeDepthLimit(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [l1.yaml]\n")
	writeTestFile(t, fs, "/app/l1.yaml", "include: [l2.yaml]\n")
	writeTestFile(t, fs, "/app/l2.yaml", "value: deep\n")

	v := includeTestViper(t, fs, IncludeLimits(2, DefaultIncludeMaxFiles))
	err := v.ReadInConfig()
	require.Error(t, err)

	var depthErr IncludeDepthError
	assert.True(t, errors.As(err, &depthErr))

	var includeErr IncludeError
	require.True(t, errors.As(err, &includeErr))
	assert.Equal(t, []string{
		filepath.Clean("/app/config.yaml"),
		filepath.Clean("/app/l1.yaml"),
		filepath.Clean("/app/l2.yaml"),
	}, includeErr.Chain)

	// Depth 2 allows the root plus one include level.
	fs2 := afero.NewMemMapFs()
	writeTestFile(t, fs2, "/app/config.yaml", "include: [l1.yaml]\n")
	writeTestFile(t, fs2, "/app/l1.yaml", "value: one\n")
	v2 := includeTestViper(t, fs2, IncludeLimits(2, DefaultIncludeMaxFiles))
	require.NoError(t, v2.ReadInConfig())
	assert.Equal(t, "one", v2.GetString("value"))
}

func TestIncludeFileCountLimit(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml, b.yaml]\n")
	writeTestFile(t, fs, "/app/a.yaml", "a: yes\n")
	writeTestFile(t, fs, "/app/b.yaml", "b: yes\n")

	v := includeTestViper(t, fs, IncludeLimits(DefaultIncludeMaxDepth, 2))
	err := v.ReadInConfig()
	require.Error(t, err)

	var countErr IncludeFileCountError
	assert.True(t, errors.As(err, &countErr))
}

func TestIncludeCaseVariantKeyConflict(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml]\nInclude: [b.yaml]\n")
	writeTestFile(t, fs, "/app/a.yaml", "a: yes\n")
	writeTestFile(t, fs, "/app/b.yaml", "b: yes\n")

	v := includeTestViper(t, fs)
	err := v.ReadInConfig()
	require.Error(t, err)

	var conflictErr IncludeKeyConflictError
	assert.True(t, errors.As(err, &conflictErr))
	assert.Contains(t, err.Error(), "conflicting include keys")

	// A single capitalized declaration is accepted.
	fs2 := afero.NewMemMapFs()
	writeTestFile(t, fs2, "/app/config.yaml", "Include: [a.yaml]\n")
	writeTestFile(t, fs2, "/app/a.yaml", "a: yes\n")
	v2 := includeTestViper(t, fs2)
	require.NoError(t, v2.ReadInConfig())
	assert.Equal(t, "yes", v2.GetString("a"))
}

func TestIncludeCustomKeyDelimiter(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/shared.yaml", "server:\n  host: shared\n  port: 1111\n")
	writeTestFile(t, fs, "/app/config.yaml", "include: [shared.yaml]\nserver:\n  host: root\n")

	v := includeTestViper(t, fs, KeyDelimiter("::"))
	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, "root", v.GetString("server::host"))
	assert.Equal(t, 1111, v.GetInt("server::port"))
	assert.Nil(t, v.Get("include"))
}

func TestIncludeIsOptIn(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [a.yaml]\ninclude_present: yes\n")

	v := New()
	v.SetFs(fs)
	v.SetConfigFile("/app/config.yaml")
	require.NoError(t, v.ReadInConfig())

	// Without the option the key is treated as ordinary business data.
	assert.Contains(t, v.AllSettings(), "include")
	assert.Equal(t, []any{"a.yaml"}, v.Get("include"))
	assert.Equal(t, "yes", v.GetString("include_present"))
}

func TestIncludeRelativePathResolution(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [conf.d/a.yaml]\n")
	writeTestFile(t, fs, "/app/conf.d/a.yaml", "include: [../shared/common.yaml]\nfrom_a: true\n")
	writeTestFile(t, fs, "/app/shared/common.yaml", "common: yes\n")

	v := includeTestViper(t, fs)
	require.NoError(t, v.ReadInConfig())
	assert.True(t, v.GetBool("from_a"))
	assert.Equal(t, "yes", v.GetString("common"))
}

func TestIncludeMergeInConfigKeepsOldOnFailure(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/first.yaml", "first: 1\n")
	writeTestFile(t, fs, "/app/config.yaml", "include: [missing.yaml]\n")

	v := includeTestViper(t, fs)
	v.SetConfigFile("/app/first.yaml")
	require.NoError(t, v.MergeInConfig())

	v.SetConfigFile("/app/config.yaml")
	require.Error(t, v.MergeInConfig())
	assert.Equal(t, 1, v.GetInt("first"))
}

func TestIncludeContentRereadOnReload(t *testing.T) {
	t.Parallel()

	base := afero.NewMemMapFs()
	writeTestFile(t, base, "/app/shared.yaml", "value: first\n")
	writeTestFile(t, base, "/app/a.yaml", "include: [shared.yaml]\n")
	writeTestFile(t, base, "/app/b.yaml", "include: [shared.yaml]\n")
	writeTestFile(t, base, "/app/config.yaml", "include: [a.yaml, b.yaml]\n")

	counting := newCountingFs(base)
	v := includeTestViper(t, counting)

	require.NoError(t, v.ReadInConfig())
	assert.Equal(t, "first", v.GetString("value"))
	assert.Equal(t, 1, counting.opens[filepath.Clean("/app/shared.yaml")])

	// Changed content is picked up on the next load, even though within a
	// single load the shared file was only read once.
	writeTestFile(t, base, "/app/shared.yaml", "value: second\n")

	require.NoError(t, v.ReadInConfig())
	assert.Equal(t, "second", v.GetString("value"))
	assert.Equal(t, 2, counting.opens[filepath.Clean("/app/shared.yaml")])
}

func TestIncludeInvalidEntryType(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: [123]\n")

	v := includeTestViper(t, fs)
	err := v.ReadInConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must contain only file paths")
}

func TestIncludeNonListValue(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/app/config.yaml", "include: a.yaml\n")

	v := includeTestViper(t, fs)
	err := v.ReadInConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a list of file paths")
}
