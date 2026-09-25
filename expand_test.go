package viper

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetExpandedInterpolation(t *testing.T) {
	v := New()
	v.Set("host", "localhost")
	v.Set("port", 8080)
	v.Set("url", "http://${host}:${port}/api")

	got, err := v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/api", got)
}

func TestGetExpandedWholeValuePreservesType(t *testing.T) {
	v := New()
	v.Set("list", []int{1, 2, 3})
	v.Set("alias", "${list}")
	v.Set("num", 42)
	v.Set("numalias", "${num}")

	got, err := v.GetExpanded("alias")
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, got)

	got, err = v.GetExpanded("numalias")
	require.NoError(t, err)
	assert.Equal(t, 42, got)
}

func TestGetExpandedChainedReferences(t *testing.T) {
	v := New()
	v.Set("a", "${b}")
	v.Set("b", "${c}")
	v.Set("c", "done")

	got, err := v.GetExpanded("a")
	require.NoError(t, err)
	assert.Equal(t, "done", got)
}

func TestGetExpandedPlainGetUnaffected(t *testing.T) {
	v := New()
	v.Set("host", "localhost")
	v.Set("url", "http://${host}")

	// Plain Get does not expand references.
	assert.Equal(t, "http://${host}", v.Get("url"))
}

func TestGetExpandedCycle(t *testing.T) {
	v := New()
	v.Set("a", "${b}")
	v.Set("b", "${a}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var cycleErr ReferenceCycleError
	require.ErrorAs(t, err, &cycleErr)
	assert.Equal(t, []string{"a", "b", "a"}, cycleErr.Chain)
	assert.Equal(t, "reference cycle detected: a -> b -> a", err.Error())

	var refErr ReferenceError
	require.ErrorAs(t, err, &refErr)
}

func TestGetExpandedSelfCycle(t *testing.T) {
	v := New()
	v.Set("a", "${a}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var cycleErr ReferenceCycleError
	require.ErrorAs(t, err, &cycleErr)
	assert.Equal(t, []string{"a", "a"}, cycleErr.Chain)
}

func TestGetExpandedMissingReference(t *testing.T) {
	v := New()
	v.Set("a", "prefix-${does.not.exist}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var missingErr ReferenceMissingError
	require.ErrorAs(t, err, &missingErr)
	assert.Equal(t, "does.not.exist", missingErr.Key)
	assert.Equal(t, []string{"a", "does.not.exist"}, missingErr.Chain)
	assert.Equal(t, "override", missingErr.Source)
	assert.Contains(t, err.Error(), "a -> does.not.exist")
}

func TestGetExpandedNonScalarInterpolation(t *testing.T) {
	v := New()
	v.Set("list", []string{"x", "y"})
	v.Set("bad", "items: ${list}")

	_, err := v.GetExpanded("bad")
	require.Error(t, err)

	var nonScalarErr ReferenceNonScalarError
	require.ErrorAs(t, err, &nonScalarErr)
	assert.Equal(t, "list", nonScalarErr.Key)
	assert.NotContains(t, err.Error(), "x")
	assert.NotContains(t, err.Error(), "y")
}

func TestGetExpandedEscapedLiteral(t *testing.T) {
	v := New()
	v.Set("esc", "$${not.a.ref}")
	v.Set("mixed", "$${literal} and ${real}")
	v.Set("real", "value")

	got, err := v.GetExpanded("esc")
	require.NoError(t, err)
	assert.Equal(t, "${not.a.ref}", got)

	got, err = v.GetExpanded("mixed")
	require.NoError(t, err)
	assert.Equal(t, "${literal} and value", got)
}

func TestGetExpandedEnvOverride(t *testing.T) {
	v := New()
	v.AutomaticEnv()
	t.Setenv("HOST", "envhost")

	v.SetConfigType("json")
	require.NoError(t, v.ReadConfig(strings.NewReader(
		`{"host": "cfghost", "port": 8080, "url": "http://${host}:${port}"}`)))

	got, err := v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://envhost:8080", got)
}

func TestGetExpandedEnvReferenceSource(t *testing.T) {
	v := New()
	v.BindEnv("broken")
	t.Setenv("BROKEN", "${missing.key}")

	_, err := v.GetExpanded("broken")
	require.Error(t, err)

	var missingErr ReferenceMissingError
	require.ErrorAs(t, err, &missingErr)
	assert.Equal(t, "env", missingErr.Source)
}

func TestGetExpandedDepthLimit(t *testing.T) {
	v := New()
	v.SetMaxReferenceDepth(2)
	v.Set("a", "${b}")
	v.Set("b", "${c}")
	v.Set("c", "${d}")
	v.Set("d", "end")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var depthErr ReferenceDepthError
	require.ErrorAs(t, err, &depthErr)
	assert.Equal(t, 2, depthErr.Limit)
	assert.Equal(t, []string{"a", "b", "c", "d"}, depthErr.Chain)
}

func TestGetExpandedCacheInvalidatedOnSet(t *testing.T) {
	v := New()
	v.Set("b", "1")
	v.Set("a", "${b}")

	got, err := v.GetExpanded("a")
	require.NoError(t, err)
	assert.Equal(t, "1", got)
	assert.NotEmpty(t, v.expandCache)

	// Mutating a value must invalidate the resolved-reference cache.
	v.Set("b", "2")
	assert.Empty(t, v.expandCache)

	got, err = v.GetExpanded("a")
	require.NoError(t, err)
	assert.Equal(t, "2", got)
}

func TestGetExpandedCacheInvalidatedOnReadConfig(t *testing.T) {
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.ReadConfig(strings.NewReader(`{"b": "1", "a": "${b}"}`)))

	got, err := v.GetExpanded("a")
	require.NoError(t, err)
	assert.Equal(t, "1", got)

	require.NoError(t, v.ReadConfig(strings.NewReader(`{"b": "2", "a": "${b}"}`)))

	got, err = v.GetExpanded("a")
	require.NoError(t, err)
	assert.Equal(t, "2", got)
}

func TestGetExpandedSameReferenceResolvedOnce(t *testing.T) {
	v := New()
	v.BindEnv("shared")
	t.Setenv("SHARED", "first")
	v.Set("b", "${shared}")
	v.Set("c", "${shared}")
	v.Set("top", "${b} ${c} ${shared}")

	got, err := v.GetExpanded("top")
	require.NoError(t, err)
	assert.Equal(t, "first first first", got)

	// The reference was resolved once and cached: changing the underlying
	// environment variable does not trigger re-resolution...
	t.Setenv("SHARED", "second")

	got, err = v.GetExpanded("top")
	require.NoError(t, err)
	assert.Equal(t, "first first first", got)

	// ...until a mutation invalidates the cache.
	v.Set("unrelated", true)

	got, err = v.GetExpanded("top")
	require.NoError(t, err)
	assert.Equal(t, "second second second", got)
}

func TestGetExpandedSensitivePropagation(t *testing.T) {
	v := New()
	v.Set("db.password", "${missing.secret}")
	v.Set("url", "${db.password}")
	v.MarkSensitive("db.password")

	_, err := v.GetExpanded("url")
	require.Error(t, err)

	var missingErr ReferenceMissingError
	require.ErrorAs(t, err, &missingErr)

	// Sensitivity propagates along the dependency chain.
	assert.True(t, missingErr.Sensitive)
	assert.Equal(t, []string{"url", "db.password", "missing.secret"}, missingErr.Chain)
}

func TestGetExpandedSensitiveValueNeverInDiagnostics(t *testing.T) {
	secret := "s3cr3t-value"

	v := New()
	v.Set("credentials", []string{secret})
	v.Set("bad", "token: ${credentials}")
	v.MarkSensitive("credentials")

	_, err := v.GetExpanded("bad")
	require.Error(t, err)

	var nonScalarErr ReferenceNonScalarError
	require.ErrorAs(t, err, &nonScalarErr)
	assert.True(t, nonScalarErr.Sensitive)

	// The diagnostic only shows paths and sources, never the secret value.
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "credentials")
	assert.Contains(t, err.Error(), "override")
}

func TestGetExpandedCycleErrorContainsNoValues(t *testing.T) {
	v := New()
	v.Set("a", "${b}")
	v.Set("b", "${a}")
	v.MarkSensitive("a")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var cycleErr ReferenceCycleError
	require.ErrorAs(t, err, &cycleErr)
	assert.True(t, cycleErr.Sensitive)
	assert.NotContains(t, err.Error(), "${")
}

func TestGetExpandedNestedCollections(t *testing.T) {
	v := New()
	v.Set("host", "localhost")
	v.Set("nested", map[string]any{
		"addr":  "http://${host}",
		"ports": []any{"${host}:1", "${host}:2"},
	})

	got, err := v.GetExpanded("nested")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"addr":  "http://localhost",
		"ports": []any{"localhost:1", "localhost:2"},
	}, got)
}

func TestGetExpandedMissingKey(t *testing.T) {
	v := New()

	got, err := v.GetExpanded("nope")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestGetExpandedNoReferences(t *testing.T) {
	v := New()
	v.Set("plain", "just a string")

	got, err := v.GetExpanded("plain")
	require.NoError(t, err)
	assert.Equal(t, "just a string", got)
}

func TestParseTemplate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []templatePart
	}{
		{
			name:  "plain",
			input: "hello",
			want:  []templatePart{{text: "hello"}},
		},
		{
			name:  "whole reference",
			input: "${a.b}",
			want:  []templatePart{{ref: "a.b", isRef: true}},
		},
		{
			name:  "mixed",
			input: "x ${a} y ${b} z",
			want: []templatePart{
				{text: "x "},
				{ref: "a", isRef: true},
				{text: " y "},
				{ref: "b", isRef: true},
				{text: " z"},
			},
		},
		{
			name:  "escaped",
			input: "$${a}",
			want:  []templatePart{{text: "${a}"}},
		},
		{
			name:  "unterminated",
			input: "x ${a",
			want:  []templatePart{{text: "x ${a"}},
		},
		{
			name:  "empty reference",
			input: "x ${} y",
			want:  []templatePart{{text: "x ${} y"}},
		},
		{
			name:  "whitespace trimmed",
			input: "${ a.b }",
			want:  []templatePart{{ref: "a.b", isRef: true}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseTemplate(tc.input))
		})
	}
}

func TestReferenceErrorInterface(t *testing.T) {
	var _ ReferenceError = ReferenceCycleError{}
	var _ ReferenceError = ReferenceMissingError{}
	var _ ReferenceError = ReferenceNonScalarError{}
	var _ ReferenceError = ReferenceDepthError{}

	// All structured errors match errors.As with the ReferenceError interface.
	err := error(ReferenceCycleError{Chain: []string{"a", "a"}})

	var refErr ReferenceError
	require.ErrorAs(t, err, &refErr)
}

func TestGetExpandedPackageLevel(t *testing.T) {
	Reset()
	Set("host", "localhost")
	Set("url", "http://${host}")

	got, err := GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost", got)

	Reset()
}

func TestGetExpandedErrorsAreStructured(t *testing.T) {
	v := New()
	v.Set("a", "${b}")
	v.Set("b", "${a}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)
	assert.True(t, errors.As(err, new(ReferenceError)))
}
