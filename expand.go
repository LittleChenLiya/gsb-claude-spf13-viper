package viper

import (
	"fmt"
	"strings"

	"github.com/spf13/cast"
)

// DefaultMaxReferenceDepth is the default maximum number of reference hops
// followed while expanding configuration references before giving up.
const DefaultMaxReferenceDepth = 100

// ReferenceError is the common interface for structured errors produced while
// expanding configuration references.
//
// Reference errors never contain configuration values: they only report the
// key paths involved and the source layer a reference expression was found
// in, so they are safe to log even when sensitive values are referenced.
type ReferenceError interface {
	error

	referenceError()
}

// ReferenceCycleError denotes a circular chain of configuration references.
//
// Chain holds the closed loop of keys, e.g. ["a", "b", "a"].
type ReferenceCycleError struct {
	Chain     []string
	Source    string
	Sensitive bool
}

func (e ReferenceCycleError) referenceError() {}

// Error returns the formatted error. It only contains key paths.
func (e ReferenceCycleError) Error() string {
	return fmt.Sprintf("reference cycle detected: %s", strings.Join(e.Chain, " -> "))
}

// ReferenceMissingError denotes a reference to a key that does not exist.
type ReferenceMissingError struct {
	Key       string
	Chain     []string
	Source    string
	Sensitive bool
}

func (e ReferenceMissingError) referenceError() {}

// Error returns the formatted error. It only contains key paths and the
// source layer the reference expression was found in.
func (e ReferenceMissingError) Error() string {
	return fmt.Sprintf("unresolved reference %q: key not found (source: %s, chain: %s)",
		e.Key, e.Source, strings.Join(e.Chain, " -> "))
}

// ReferenceNonScalarError denotes a reference to a collection (map or slice)
// embedded inside a larger string. Only whole-value references preserve
// collection types; interpolation into a string requires a scalar.
type ReferenceNonScalarError struct {
	Key       string
	Chain     []string
	Source    string
	Sensitive bool
}

func (e ReferenceNonScalarError) referenceError() {}

// Error returns the formatted error. It only contains key paths and the
// source layer the reference expression was found in.
func (e ReferenceNonScalarError) Error() string {
	return fmt.Sprintf("cannot interpolate non-scalar value from %q into a string (source: %s, chain: %s)",
		e.Key, e.Source, strings.Join(e.Chain, " -> "))
}

// ReferenceDepthError denotes a reference chain that exceeded the configured
// maximum expansion depth.
type ReferenceDepthError struct {
	Limit     int
	Chain     []string
	Sensitive bool
}

func (e ReferenceDepthError) referenceError() {}

// Error returns the formatted error. It only contains key paths.
func (e ReferenceDepthError) Error() string {
	return fmt.Sprintf("reference expansion exceeded maximum depth of %d (chain: %s)",
		e.Limit, strings.Join(e.Chain, " -> "))
}

// templatePart is a segment of a parsed string: either literal text or a
// reference to another configuration path.
type templatePart struct {
	text  string
	ref   string
	isRef bool
}

// parseTemplate splits s into literal and reference parts.
//
// References use the syntax ${path.to.key}. The escape sequence $${ produces
// a literal "${". An unterminated "${" is treated as literal text.
func parseTemplate(s string) []templatePart {
	var parts []templatePart

	var lit strings.Builder

	flushLiteral := func() {
		if lit.Len() > 0 {
			parts = append(parts, templatePart{text: lit.String()})
			lit.Reset()
		}
	}

	i := 0
	for i < len(s) {
		// Escaped literal: "$${" renders as "${".
		if s[i] == '$' && i+2 < len(s) && s[i+1] == '$' && s[i+2] == '{' {
			lit.WriteString("${")
			i += 3

			continue
		}

		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			rest := s[i+2:]
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				// Unterminated reference: treat the remainder as literal text.
				lit.WriteString(s[i:])
				i = len(s)

				continue
			}

			ref := strings.TrimSpace(rest[:end])
			if ref == "" {
				// Empty reference: treat as literal text.
				lit.WriteString(s[i : i+2+end+1])
				i += 2 + end + 1

				continue
			}

			flushLiteral()
			parts = append(parts, templatePart{ref: ref, isRef: true})
			i += 2 + end + 1

			continue
		}

		lit.WriteByte(s[i])
		i++
	}

	flushLiteral()

	return parts
}

// isScalar reports whether val can be interpolated into a string.
func isScalar(val any) bool {
	switch val.(type) {
	case string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return true
	}

	return false
}

// GetExpanded retrieves the value associated with the key and expands any
// configuration references of the form ${path.to.key} found in string values.
//
// The raw value is first resolved using the standard Viper precedence
// (override, flag, env, config file, key/value store, default); references
// are expanded afterwards. A string consisting of a single whole-value
// reference resolves to the referenced value with its original type
// preserved (e.g. a list stays a list). References embedded in a larger
// string are interpolated and require scalar values.
//
// Cycles, missing keys, non-scalar interpolation and excessive depth are
// reported as structured ReferenceError values that never contain
// configuration values.
//
// Note: plain Get does not expand references; expansion is opt-in through
// this method.
func GetExpanded(key string) (any, error) { return v.GetExpanded(key) }

// GetExpanded retrieves the value associated with the key and expands any
// configuration references found in string values. See the package-level
// GetExpanded documentation for details.
func (v *Viper) GetExpanded(key string) (any, error) {
	lcaseKey := strings.ToLower(key)

	val := v.find(lcaseKey, true)
	if val == nil {
		return nil, nil
	}

	return v.resolveValue(lcaseKey, val, v.valueSource(lcaseKey),
		[]string{lcaseKey}, 0, v.isSensitive(lcaseKey))
}

// MarkSensitive marks the given paths as sensitive. Sensitivity propagates
// along reference dependency chains: any key that directly or transitively
// references a sensitive path is treated as sensitive in diagnostics.
// Diagnostics for sensitive resolutions only ever report key paths and
// source layers, never values.
func MarkSensitive(paths ...string) { v.MarkSensitive(paths...) }

// MarkSensitive marks the given paths as sensitive. See the package-level
// MarkSensitive documentation for details.
func (v *Viper) MarkSensitive(paths ...string) {
	for _, p := range paths {
		v.sensitivePaths[strings.ToLower(p)] = true
	}
}

// SetMaxReferenceDepth sets the maximum number of reference hops followed
// during a single expansion before a ReferenceDepthError is returned.
func SetMaxReferenceDepth(n int) { v.SetMaxReferenceDepth(n) }

// SetMaxReferenceDepth sets the maximum number of reference hops followed
// during a single expansion before a ReferenceDepthError is returned.
func (v *Viper) SetMaxReferenceDepth(n int) {
	v.maxReferenceDepth = n
}

// isSensitive reports whether the given (already lowercased) key has been
// marked as sensitive.
func (v *Viper) isSensitive(lcaseKey string) bool {
	return v.sensitivePaths[lcaseKey]
}

// invalidateExpandCache clears the resolved-reference cache. It is called by
// every mutating operation so that expansions always observe fresh values.
func (v *Viper) invalidateExpandCache() {
	v.expandCache = make(map[string]any)
}

// resolveValue expands references in val, which was resolved for key from
// the given source layer. chain holds the keys currently being resolved
// (innermost last) and is used for cycle detection and diagnostics.
func (v *Viper) resolveValue(key string, val any, source string, chain []string, depth int, sensitive bool) (any, error) {
	switch typed := val.(type) {
	case string:
		return v.resolveString(key, typed, source, chain, depth, sensitive)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, item := range typed {
			resolved, err := v.resolveValue(key, item, source, chain, depth, sensitive)
			if err != nil {
				return nil, err
			}
			out[k] = resolved
		}

		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			resolved, err := v.resolveValue(key, item, source, chain, depth, sensitive)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}

		return out, nil
	default:
		return val, nil
	}
}

// resolveString expands references in the string s.
func (v *Viper) resolveString(key, s, source string, chain []string, depth int, sensitive bool) (any, error) {
	parts := parseTemplate(s)

	hasRef := false
	for _, p := range parts {
		if p.isRef {
			hasRef = true

			break
		}
	}
	if !hasRef {
		// No references, but escape sequences may have been consumed:
		// reassemble the literal text.
		var sb strings.Builder
		for _, p := range parts {
			sb.WriteString(p.text)
		}

		return sb.String(), nil
	}

	// Whole-value reference: preserve the referenced value's original type.
	if len(parts) == 1 && parts[0].isRef {
		return v.resolveReference(parts[0].ref, source, chain, depth, sensitive)
	}

	var sb strings.Builder
	for _, p := range parts {
		if !p.isRef {
			sb.WriteString(p.text)

			continue
		}

		refVal, err := v.resolveReference(p.ref, source, chain, depth, sensitive)
		if err != nil {
			return nil, err
		}

		if !isScalar(refVal) {
			return nil, ReferenceNonScalarError{
				Key:       strings.ToLower(p.ref),
				Chain:     appendChain(chain, p.ref),
				Source:    source,
				Sensitive: sensitive || v.isSensitive(strings.ToLower(p.ref)),
			}
		}

		sb.WriteString(cast.ToString(refVal))
	}

	return sb.String(), nil
}

// resolveReference resolves a single ${ref} expression found in a value
// obtained from source, while chain holds the keys currently being resolved.
func (v *Viper) resolveReference(ref, source string, chain []string, depth int, sensitive bool) (any, error) {
	refKey := strings.ToLower(ref)
	refSensitive := sensitive || v.isSensitive(refKey)
	refChain := appendChain(chain, ref)

	for _, c := range chain {
		if c == refKey {
			return nil, ReferenceCycleError{
				Chain:     refChain,
				Source:    source,
				Sensitive: refSensitive,
			}
		}
	}

	if depth+1 > v.maxReferenceDepth {
		return nil, ReferenceDepthError{
			Limit:     v.maxReferenceDepth,
			Chain:     refChain,
			Sensitive: refSensitive,
		}
	}

	// Resolved references are cached so each reference is only resolved once;
	// the cache is invalidated by any mutating operation.
	if cached, ok := v.expandCache[refKey]; ok {
		return cached, nil
	}

	raw := v.find(refKey, true)
	if raw == nil {
		return nil, ReferenceMissingError{
			Key:       refKey,
			Chain:     refChain,
			Source:    source,
			Sensitive: refSensitive,
		}
	}

	resolved, err := v.resolveValue(refKey, raw, v.valueSource(refKey), refChain, depth+1, refSensitive)
	if err != nil {
		return nil, err
	}

	v.expandCache[refKey] = resolved

	return resolved, nil
}

// appendChain appends ref to chain without mutating the shared backing array.
func appendChain(chain []string, ref string) []string {
	out := make([]string, len(chain)+1)
	copy(out, chain)
	out[len(chain)] = strings.ToLower(ref)

	return out
}

// valueSource reports which layer provides the value for the given
// (already lowercased) key, following the standard Viper precedence.
// It is used for diagnostics only.
func (v *Viper) valueSource(lcaseKey string) string {
	lcaseKey = v.realKey(lcaseKey)
	path := strings.Split(lcaseKey, v.keyDelim)

	if v.searchMap(v.override, path) != nil {
		return "override"
	}

	if flag, exists := v.pflags[lcaseKey]; exists && flag.HasChanged() {
		return "flag"
	}

	if v.automaticEnvApplied {
		envKey := strings.Join(append(v.parents, lcaseKey), ".")
		if _, ok := v.getEnv(v.mergeWithEnvPrefix(envKey)); ok {
			return "env"
		}
	}
	if envkeys, exists := v.env[lcaseKey]; exists {
		for _, envkey := range envkeys {
			if _, ok := v.getEnv(envkey); ok {
				return "env"
			}
		}
	}

	if v.searchIndexableWithPathPrefixes(v.config, path) != nil {
		return "config"
	}

	if v.searchMap(v.kvstore, path) != nil {
		return "kvstore"
	}

	if v.searchMap(v.defaults, path) != nil {
		return "default"
	}

	if _, exists := v.pflags[lcaseKey]; exists {
		return "flag"
	}

	return "unknown"
}
