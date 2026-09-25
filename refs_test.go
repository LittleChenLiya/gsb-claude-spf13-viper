package viper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReferenceInterpolationHostPort(t *testing.T) {
	v := New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString("host: example.com\nport: 8080\nurl: \"http://${host}:${port}/api\"\n"))
	require.NoError(t, err)

	val, err := v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://example.com:8080/api", val)
}

func TestReferenceWholeValuePreservesType(t *testing.T) {
	v := New()
	v.Set("servers", []string{"alpha", "beta"})
	v.Set("primary", "${servers}")
	v.Set("limits", map[string]any{"cpu": 2})
	v.Set("limitsAlias", "${limits}")

	val, err := v.GetExpanded("primary")
	require.NoError(t, err)
	assert.Equal(t, []any{"alpha", "beta"}, val)

	mval, err := v.GetExpanded("limitsAlias")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"cpu": 2}, mval)
}

func TestReferenceCycleShowsClosedLoop(t *testing.T) {
	v := New()
	v.Set("a", "${b}")
	v.Set("b", "${a}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var cycleErr ReferenceCycleError
	require.True(t, errors.As(err, &cycleErr), "expected ReferenceCycleError, got %T", err)
	assert.Equal(t, []string{"a", "b", "a"}, cycleErr.ReferenceChain())
	assert.Equal(t, ReferenceErrorCycle, cycleErr.ReferenceKind())
	assert.Contains(t, err.Error(), "a -> b -> a")
}

func TestReferenceMissingTarget(t *testing.T) {
	v := New()
	v.Set("a", "prefix-${nope}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)

	var missingErr ReferenceMissingError
	require.True(t, errors.As(err, &missingErr), "expected ReferenceMissingError, got %T", err)
	assert.Equal(t, "nope", missingErr.Target)
	assert.Equal(t, []string{"a", "nope"}, missingErr.ReferenceChain())
	assert.Equal(t, ReferenceErrorMissing, missingErr.ReferenceKind())
}

func TestReferenceNonScalarEmbeddedInString(t *testing.T) {
	v := New()
	v.Set("list", []string{"s3cr3t-item"})
	v.Set("bad", "items: ${list}")

	_, err := v.GetExpanded("bad")
	require.Error(t, err)

	var nonScalarErr ReferenceNonScalarError
	require.True(t, errors.As(err, &nonScalarErr), "expected ReferenceNonScalarError, got %T", err)
	assert.Equal(t, "list", nonScalarErr.Target)
	assert.Equal(t, []string{"bad", "list"}, nonScalarErr.ReferenceChain())
	// The referenced value must never leak into the error message.
	assert.NotContains(t, err.Error(), "s3cr3t-item")
}

func TestReferenceSensitivePropagationAndSafeDiagnostics(t *testing.T) {
	v := New()
	v.Set("db.password", "s3cr3t-value")
	v.Set("db.dsn", "postgres://localhost/${db.password}")
	v.MarkSensitive("db.password")

	diags, err := v.ExplainReferences("db.dsn")
	require.NoError(t, err)
	require.Len(t, diags, 2)

	byPath := map[string]ReferenceDiagnostic{}
	for _, d := range diags {
		byPath[d.Path] = d
	}
	require.Contains(t, byPath, "db.dsn")
	require.Contains(t, byPath, "db.password")
	// Sensitivity propagates along the dependency edge.
	assert.True(t, byPath["db.password"].Sensitive)
	assert.True(t, byPath["db.dsn"].Sensitive)
	assert.Equal(t, []string{"db.password"}, byPath["db.dsn"].Dependencies)
	assert.Equal(t, sourceOverride, byPath["db.dsn"].Source)

	// Safe diagnostics never expose values.
	assert.NotContains(t, fmt.Sprintf("%+v", diags), "s3cr3t-value")
}

func TestReferenceSafeFailureReport(t *testing.T) {
	v := New()
	v.Set("db.creds", map[string]any{"password": "s3cr3t-value"})
	v.Set("dsn", "creds: ${db.creds}")
	v.MarkSensitive("db.creds")

	diags, err := v.ExplainReferences("dsn")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cr3t-value")
	assert.NotContains(t, fmt.Sprintf("%+v", diags), "s3cr3t-value")
	require.NotEmpty(t, diags)
	for _, d := range diags {
		assert.True(t, d.Sensitive, "expected %s to be marked sensitive", d.Path)
	}
}

func TestReferenceCacheInvalidatedOnChange(t *testing.T) {
	v := New()
	v.Set("host", "first")
	v.Set("url", "http://${host}")

	val, err := v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://first", val)
	before := v.refResolveCount

	// Cached: no new resolutions.
	val, err = v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://first", val)
	assert.Equal(t, before, v.refResolveCount)

	// Changing a value invalidates the cache.
	v.Set("host", "second")
	val, err = v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://second", val)
	assert.Greater(t, v.refResolveCount, before)
}

func TestReferenceEnvOverride(t *testing.T) {
	t.Setenv("HOST", "env.example.com")

	v := New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString("host: file.example.com\nurl: \"http://${host}\"\n")))
	v.AutomaticEnv()

	val, err := v.GetExpanded("url")
	require.NoError(t, err)
	assert.Equal(t, "http://env.example.com", val)

	diags, err := v.ExplainReferences("url")
	require.NoError(t, err)
	byPath := map[string]ReferenceDiagnostic{}
	for _, d := range diags {
		byPath[d.Path] = d
	}
	require.Contains(t, byPath, "host")
	assert.Equal(t, sourceEnv, byPath["host"].Source)
	assert.Equal(t, sourceConfig, byPath["url"].Source)
}

func TestReferenceEscapedLiteral(t *testing.T) {
	v := New()
	v.Set("literal", "$${not.a.ref}")
	v.Set("plain", "costs $5 and keeps {braces}")

	val, err := v.GetExpanded("literal")
	require.NoError(t, err)
	assert.Equal(t, "${not.a.ref}", val)

	val, err = v.GetExpanded("plain")
	require.NoError(t, err)
	assert.Equal(t, "costs $5 and keeps {braces}", val)
}

func TestReferenceDepthLimit(t *testing.T) {
	v := New()
	for i := 0; i < 10; i++ {
		v.Set(fmt.Sprintf("k%d", i), fmt.Sprintf("${k%d}", i+1))
	}
	v.Set("k10", "leaf")
	v.SetReferenceMaxDepth(3)

	_, err := v.GetExpanded("k0")
	require.Error(t, err)

	var depthErr ReferenceDepthError
	require.True(t, errors.As(err, &depthErr), "expected ReferenceDepthError, got %T", err)
	assert.Equal(t, 3, depthErr.Limit)
	assert.Equal(t, []string{"k0", "k1", "k2", "k3"}, depthErr.ReferenceChain())
	assert.Equal(t, ReferenceErrorDepth, depthErr.ReferenceKind())
}

func TestReferenceResolvedOnlyOnce(t *testing.T) {
	v := New()
	v.Set("shared", "value")
	v.Set("bundle", map[string]any{"x": "${shared}", "y": "${shared}"})
	v.Set("other", "${shared}")

	val, err := v.GetExpanded("bundle")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"x": "value", "y": "value"}, val)
	// bundle + shared: the shared reference is resolved exactly once.
	assert.Equal(t, 2, v.refResolveCount)

	// A second key referencing the same target uses the cache.
	_, err = v.GetExpanded("other")
	require.NoError(t, err)
	assert.Equal(t, 3, v.refResolveCount)
}

func TestGetDoesNotExpandReferences(t *testing.T) {
	v := New()
	v.Set("host", "example.com")
	v.Set("url", "http://${host}")

	// Plain Get is not affected by the reference layer.
	assert.Equal(t, "http://${host}", v.Get("url"))
	assert.Equal(t, "http://${host}", v.GetString("url"))
}

func TestReferenceNestedChain(t *testing.T) {
	v := New()
	v.Set("host", "example.com")
	v.Set("base", "http://${host}")
	v.Set("api", "${base}/v1")

	val, err := v.GetExpanded("api")
	require.NoError(t, err)
	assert.Equal(t, "http://example.com/v1", val)

	diags, err := v.ExplainReferences("api")
	require.NoError(t, err)
	require.Len(t, diags, 3)
	assert.Equal(t, "api", diags[0].Path)
	assert.Equal(t, "base", diags[1].Path)
	assert.Equal(t, "host", diags[2].Path)
}

func TestReferenceErrorContainsNoValues(t *testing.T) {
	v := New()
	v.Set("a", "${b}")
	v.Set("b", "${a}")

	_, err := v.GetExpanded("a")
	require.Error(t, err)
	// Cycle messages only contain paths.
	assert.NotContains(t, err.Error(), "${")
}

func ExampleViper_GetExpanded() {
	v := New()
	v.Set("host", "example.com")
	v.Set("port", 8080)
	v.Set("url", "http://${host}:${port}/api")
	v.Set("servers", []string{"alpha", "beta"})
	v.Set("primary", "${servers}")

	url, err := v.GetExpanded("url")
	fmt.Println(url, err)

	primary, err := v.GetExpanded("primary")
	fmt.Println(primary, err)

	// Output:
	// http://example.com:8080/api <nil>
	// [alpha beta] <nil>
}

func ExampleViper_ExplainReferences() {
	v := New()
	v.Set("db.creds", map[string]any{"password": "s3cr3t-value"})
	v.Set("dsn", "creds: ${db.creds}")
	v.MarkSensitive("db.creds")

	// The safe failure report names paths and sources only; the secret value
	// never appears.
	diags, err := v.ExplainReferences("dsn")
	for _, d := range diags {
		fmt.Printf("%s (source=%s, sensitive=%t, deps=%v)\n", d.Path, d.Source, d.Sensitive, d.Dependencies)
	}
	fmt.Println("error:", err)

	// Output:
	// db.creds (source=override, sensitive=true, deps=[])
	// dsn (source=override, sensitive=true, deps=[db.creds])
	// error: reference target "db.creds" resolves to a non-scalar value and cannot be embedded in a string (dependency chain: dsn -> db.creds)
}
