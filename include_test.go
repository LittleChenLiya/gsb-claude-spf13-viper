package viper

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func includeFixture(t *testing.T, name string) string {
	t.Helper()

	return filepath.Join("testdata", "include", name)
}

func writeIncludeFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, afero.WriteFile(afero.NewOsFs(), path, []byte(content), 0o644))

	return path
}

func TestIncludesMergeOrder(t *testing.T) {
	v := NewWithOptions(WithIncludes())
	v.SetConfigFile(includeFixture(t, "root.yaml"))

	require.NoError(t, v.ReadInConfig())

	// Values from files included earlier are overridden by files included
	// later, and the root file wins over everything it includes.
	assert.Equal(t, "shared", v.GetString("sharedvalue"))
	assert.Equal(t, "a", v.GetString("avalue"))
	assert.Equal(t, "b", v.GetString("bvalue"))
	assert.Equal(t, "b", v.GetString("ab"))
	assert.Equal(t, "root", v.GetString("order"))
	assert.Equal(t, "root", v.GetString("rootvalue"))

	// The include directive itself must not leak into the configuration.
	assert.Nil(t, v.Get("include"))
	assert.NotContains(t, v.AllSettings(), "include")
}

func TestIncludesDisabledByDefault(t *testing.T) {
	v := New()
	v.SetConfigFile(includeFixture(t, "root.yaml"))

	require.NoError(t, v.ReadInConfig())

	// Without WithIncludes the include key is an ordinary config value.
	assert.Equal(t, []any{"a.yaml", "b.yaml"}, v.Get("include"))
	assert.Empty(t, v.GetString("sharedvalue"))
}

func TestIncludesEnvAndSetPriority(t *testing.T) {
	t.Setenv("APP_ORDER", "env")

	v := NewWithOptions(WithIncludes())
	v.SetConfigFile(includeFixture(t, "root.yaml"))
	v.SetEnvPrefix("app")
	v.AutomaticEnv()
	v.Set("ab", "set")

	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, "env", v.GetString("order"))
	assert.Equal(t, "set", v.GetString("ab"))
	assert.Equal(t, "shared", v.GetString("sharedvalue"))
}

// readCountingFs counts how many times each canonical path is opened.
type readCountingFs struct {
	afero.Fs

	mu    sync.Mutex
	reads map[string]int
}

func newReadCountingFs(base afero.Fs) *readCountingFs {
	return &readCountingFs{Fs: base, reads: make(map[string]int)}
}

func (f *readCountingFs) Open(name string) (afero.File, error) {
	f.mu.Lock()
	f.reads[canonicalIncludePath(name)]++
	f.mu.Unlock()

	return f.Fs.Open(name)
}

func (f *readCountingFs) readCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.reads[canonicalIncludePath(name)]
}

func TestIncludesSharedFileReadOncePerLoad(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "include: [a.yaml, b.yaml]\norder: root\n")
	writeIncludeFile(t, dir, "a.yaml", "include: [shared.yaml]\navalue: a\n")
	writeIncludeFile(t, dir, "b.yaml", "include: [shared.yaml]\nbvalue: b\n")
	shared := writeIncludeFile(t, dir, "shared.yaml", "sharedvalue: first\n")

	fs := newReadCountingFs(afero.NewOsFs())

	v := NewWithOptions(WithIncludes())
	v.SetFs(fs)
	v.SetConfigFile(root)

	require.NoError(t, v.ReadInConfig())

	// The shared file is referenced by two siblings, but only read once.
	assert.Equal(t, 1, fs.readCount(shared))
	assert.Equal(t, 1, fs.readCount(root))
	assert.Equal(t, "first", v.GetString("sharedvalue"))

	// A reload picks up new content: the cache only lives for one load.
	writeIncludeFile(t, dir, "shared.yaml", "sharedvalue: second\n")

	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, 2, fs.readCount(shared))
	assert.Equal(t, "second", v.GetString("sharedvalue"))
}

func TestIncludesFailureKeepsOldConfig(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "include: [child.yaml]\nrootvalue: root\n")
	writeIncludeFile(t, dir, "child.yaml", "childvalue: child\n")

	v := NewWithOptions(WithIncludes())
	v.SetConfigFile(root)

	require.NoError(t, v.ReadInConfig())
	require.Equal(t, "root", v.GetString("rootvalue"))
	require.Equal(t, "child", v.GetString("childvalue"))

	// Break the include graph: the old configuration must stay in place.
	writeIncludeFile(t, dir, "root.yaml", "include: [gone.yaml]\nrootvalue: new\n")

	err := v.ReadInConfig()
	require.Error(t, err)

	assert.Equal(t, "root", v.GetString("rootvalue"))
	assert.Equal(t, "child", v.GetString("childvalue"))
	assert.Empty(t, v.GetString("new"))
}

func TestIncludeCycle(t *testing.T) {
	v := NewWithOptions(WithIncludes())
	v.SetConfigFile(includeFixture(t, "cycle-a.yaml"))

	err := v.ReadInConfig()
	require.Error(t, err)

	var cycleErr IncludeCycleError
	require.ErrorAs(t, err, &cycleErr)

	// The error reports the full chain, ending with the repeated file.
	require.Len(t, cycleErr.Chain, 3)
	assert.Equal(t, cycleErr.Chain[0], cycleErr.Chain[2])
	assert.Contains(t, err.Error(), "cycle-a.yaml")
	assert.Contains(t, err.Error(), "cycle-b.yaml")
	assert.Contains(t, err.Error(), "->")
}

func TestIncludeMissingFile(t *testing.T) {
	v := NewWithOptions(WithIncludes())
	v.SetConfigFile(includeFixture(t, "missing.yaml"))

	err := v.ReadInConfig()
	require.Error(t, err)

	var includeErr IncludeError
	require.ErrorAs(t, err, &includeErr)

	// The error reports the full chain from the root to the missing file.
	require.Len(t, includeErr.Chain, 2)
	assert.Contains(t, err.Error(), "missing.yaml")
	assert.Contains(t, err.Error(), "does-not-exist.yaml")
}

func TestIncludeMaxDepth(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "include: [l1.yaml]\n")
	writeIncludeFile(t, dir, "l1.yaml", "include: [l2.yaml]\n")
	writeIncludeFile(t, dir, "l2.yaml", "value: too-deep\n")

	v := NewWithOptions(WithIncludes(), IncludeMaxDepth(2))
	v.SetConfigFile(root)

	err := v.ReadInConfig()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIncludeMaxDepth)

	var includeErr IncludeError
	require.ErrorAs(t, err, &includeErr)
	require.Len(t, includeErr.Chain, 3)
	assert.Contains(t, err.Error(), "root.yaml")
	assert.Contains(t, err.Error(), "l1.yaml")
	assert.Contains(t, err.Error(), "l2.yaml")
}

func TestIncludeMaxFiles(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "include: [f1.yaml, f2.yaml]\n")
	writeIncludeFile(t, dir, "f1.yaml", "one: 1\n")
	writeIncludeFile(t, dir, "f2.yaml", "two: 2\n")

	v := NewWithOptions(WithIncludes(), IncludeMaxFiles(2))
	v.SetConfigFile(root)

	err := v.ReadInConfig()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIncludeMaxFiles)
}

func TestIncludeCaseInsensitiveKeys(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "include: [shared.yaml]\nkey: root\n")
	writeIncludeFile(t, dir, "shared.yaml", "Key: shared\n")

	v := NewWithOptions(WithIncludes())
	v.SetConfigFile(root)

	require.NoError(t, v.ReadInConfig())

	// Keys differing only in case refer to the same value; the root file
	// wins over the included file.
	assert.Equal(t, "root", v.GetString("key"))
	assert.Equal(t, "root", v.GetString("KEY"))
	assert.Equal(t, "root", v.GetString("Key"))
}

func TestIncludeCustomKeyDelimiter(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "include: [child.yaml]\nserver:\n  host: root-host\n")
	writeIncludeFile(t, dir, "child.yaml", "server:\n  host: child-host\n  port: 8080\n")

	v := NewWithOptions(KeyDelimiter("::"), WithIncludes())
	v.SetConfigFile(root)

	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, "root-host", v.GetString("server::host"))
	assert.Equal(t, 8080, v.GetInt("server::port"))
	assert.Nil(t, v.Get("include"))
}

func TestIncludeCustomIncludeKey(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "imports: [child.yaml]\nrootvalue: root\n")
	writeIncludeFile(t, dir, "child.yaml", "childvalue: child\n")

	v := NewWithOptions(WithIncludes(), IncludeKey("imports"))
	v.SetConfigFile(root)

	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, "child", v.GetString("childvalue"))
	assert.Nil(t, v.Get("imports"))
}

func TestIncludeNestedIncludeKey(t *testing.T) {
	dir := t.TempDir()

	root := writeIncludeFile(t, dir, "root.yaml", "meta:\n  include: [child.yaml]\nrootvalue: root\n")
	writeIncludeFile(t, dir, "child.yaml", "childvalue: child\n")

	v := NewWithOptions(KeyDelimiter("::"), WithIncludes(), IncludeKey("meta::include"))
	v.SetConfigFile(root)

	require.NoError(t, v.ReadInConfig())

	assert.Equal(t, "child", v.GetString("childvalue"))
	assert.Nil(t, v.Get("meta::include"))
}
