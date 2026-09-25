package viper

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Reference expansion configuration values.
const (
	// DefaultReferenceMaxDepth is the default maximum number of nested
	// reference hops performed while resolving a single key.
	DefaultReferenceMaxDepth = 32
)

// Sources reported by reference diagnostics. They name the precedence layer
// (see the package documentation) that supplied a value, and never the value
// itself.
const (
	sourceOverride    = "override"
	sourceFlag        = "flag"
	sourceFlagDefault = "flag-default"
	sourceEnv         = "env"
	sourceConfig      = "config"
	sourceKVStore     = "kvstore"
	sourceDefault     = "default"
	sourceUnset       = "unset"
)

// Reference syntax: ${key.with.dots}. A literal reference is written with a
// doubled dollar sign: $$ followed by an opening brace yields a literal
// opening. Braces without a leading dollar sign are ordinary characters.
const (
	refOpen  = "${"
	refClose = "}"
	refEsc   = "$$"
)

// ReferenceErrorKind identifies the structured failure encountered while
// expanding configuration references.
type ReferenceErrorKind string

const (
	// ReferenceErrorCycle reports a closed reference dependency loop.
	ReferenceErrorCycle ReferenceErrorKind = "cycle"
	// ReferenceErrorMissing reports a reference target that has no value.
	ReferenceErrorMissing ReferenceErrorKind = "missing"
	// ReferenceErrorNonScalar reports a map or slice embedded inside a string.
	ReferenceErrorNonScalar ReferenceErrorKind = "non-scalar"
	// ReferenceErrorDepth reports that the maximum expansion depth was reached.
	ReferenceErrorDepth ReferenceErrorKind = "depth"
)

// ReferenceError is the common interface of all structured reference
// expansion errors. Error messages contain configuration paths and the
// dependency chain only; referenced (potentially secret) values are never
// rendered.
type ReferenceError interface {
	error
	referenceError()
	ReferenceKind() ReferenceErrorKind
	ReferenceChain() []string
}

func formatReferenceChain(chain []string) string {
	return strings.Join(chain, " -> ")
}

// ReferenceCycleError denotes a closed loop in the reference dependency graph,
// for example a -> b -> a. The chain always starts and ends with the same
// path.
type ReferenceCycleError struct {
	Chain []string
}

func (ReferenceCycleError) referenceError() {}

// ReferenceKind returns ReferenceErrorCycle.
func (ReferenceCycleError) ReferenceKind() ReferenceErrorKind { return ReferenceErrorCycle }

// ReferenceChain returns the closed loop, with the repeated path appended.
func (e ReferenceCycleError) ReferenceChain() []string { return slices.Clone(e.Chain) }

func (e ReferenceCycleError) Error() string {
	return fmt.Sprintf("reference cycle detected: %s", formatReferenceChain(e.Chain))
}

// ReferenceMissingError denotes a reference to a configuration path that has
// no value in any precedence layer.
type ReferenceMissingError struct {
	// Target is the path that could not be resolved.
	Target string
	// Chain is the dependency path from the originally requested key to Target.
	Chain []string
}

func (ReferenceMissingError) referenceError() {}

// ReferenceKind returns ReferenceErrorMissing.
func (ReferenceMissingError) ReferenceKind() ReferenceErrorKind { return ReferenceErrorMissing }

// ReferenceChain returns the dependency chain leading to the missing target.
func (e ReferenceMissingError) ReferenceChain() []string { return slices.Clone(e.Chain) }

func (e ReferenceMissingError) Error() string {
	return fmt.Sprintf("reference target %q not found (dependency chain: %s)", e.Target, formatReferenceChain(e.Chain))
}

// ReferenceNonScalarError denotes a reference whose resolved value is a
// collection (map or slice) but appears embedded in a string. Collections may
// only be taken with a whole-value reference.
type ReferenceNonScalarError struct {
	// Target is the path that resolved to a collection.
	Target string
	// Chain is the dependency path from the originally requested key to Target.
	Chain []string
}

func (ReferenceNonScalarError) referenceError() {}

// ReferenceKind returns ReferenceErrorNonScalar.
func (ReferenceNonScalarError) ReferenceKind() ReferenceErrorKind { return ReferenceErrorNonScalar }

// ReferenceChain returns the dependency chain leading to the non-scalar target.
func (e ReferenceNonScalarError) ReferenceChain() []string { return slices.Clone(e.Chain) }

func (e ReferenceNonScalarError) Error() string {
	return fmt.Sprintf("reference target %q resolves to a non-scalar value and cannot be embedded in a string (dependency chain: %s)", e.Target, formatReferenceChain(e.Chain))
}

// ReferenceDepthError denotes that expanding a key required more nested
// reference hops than the configured maximum.
type ReferenceDepthError struct {
	// Limit is the maximum depth that was reached.
	Limit int
	// Chain is the dependency path up to the point the limit was reached.
	Chain []string
}

func (ReferenceDepthError) referenceError() {}

// ReferenceKind returns ReferenceErrorDepth.
func (ReferenceDepthError) ReferenceKind() ReferenceErrorKind { return ReferenceErrorDepth }

// ReferenceChain returns the dependency chain up to the depth limit.
func (e ReferenceDepthError) ReferenceChain() []string { return slices.Clone(e.Chain) }

func (e ReferenceDepthError) Error() string {
	return fmt.Sprintf("reference expansion exceeded maximum depth of %d (dependency chain: %s)", e.Limit, formatReferenceChain(e.Chain))
}

// ReferenceDiagnostic describes one configuration path involved in expanding
// a key. It deliberately exposes no values, only paths and the precedence
// layer that supplied them, so it is safe to present even for sensitive data.
type ReferenceDiagnostic struct {
	// Path is the lower-cased configuration path.
	Path string
	// Source names the precedence layer that supplied the raw value
	// ("override", "flag", "flag-default", "env", "config", "kvstore" or
	// "default").
	Source string
	// Sensitive reports that the path was marked sensitive or depends on a
	// sensitive path.
	Sensitive bool
	// Dependencies lists the reference targets used while expanding Path.
	Dependencies []string
}

// refCacheEntry stores a successfully expanded value between calls.
type refCacheEntry struct {
	value     any
	source    string
	sensitive bool
	deps      []string
}

// refEntry tracks one key during a single expansion run.
type refEntry struct {
	path      string
	source    string
	value     any
	deps      []string
	sensitive bool
	pending   bool
	err       ReferenceError
}

type refResolver struct {
	v        *Viper
	maxDepth int
	chain    []string
	depth    int
	memo     map[string]*refEntry
	order    []string
}

// GetExpanded returns the value for key after expanding string configuration
// references using the syntax ${other.key}.
//
// As with Viper.Get, the raw value is selected with Viper's normal
// precedence (override, flag, env, config, key/value store, default). The
// reference layer runs afterwards, so references are resolved against final
// raw values.
//
// A string that consists of a single whole-value reference, for example the
// value of a key set to a reference to a list, keeps the referenced value's
// original type: a list stays a list and a map stays a map. References
// embedded inside a larger string are interpolated as text and may only
// reference scalar values.
//
// Reference expansion is opt-in: Viper.Get never expands references.
//
// Structured ReferenceError values report cycles, missing targets,
// non-scalar interpolation and depth failures with the dependency chain but
// without any referenced values.
func (v *Viper) GetExpanded(key string) (any, error) {
	r := v.newRefResolver()
	val, refErr := r.resolve(strings.ToLower(key))
	if refErr != nil {
		return nil, refErr
	}
	return val, nil
}

// ExplainReferences expands key and returns safe diagnostics for every path
// involved: the path itself, the precedence layer supplying its raw value,
// whether the path is sensitive, and the paths it references. Expanded values
// are never included, so secret values cannot leak through the report. The
// returned error is non-nil under the same conditions as Viper.GetExpanded;
// diagnostics are returned even when expansion fails.
func (v *Viper) ExplainReferences(key string) ([]ReferenceDiagnostic, error) {
	r := v.newRefResolver()
	_, refErr := r.resolve(strings.ToLower(key))
	return r.diagnostics(), refErr
}

// MarkSensitive marks configuration paths as sensitive. Sensitivity is
// propagated through references: a key that references a sensitive path (at
// any nesting depth) is itself reported as sensitive. Marking a parent path
// also marks every path below it.
func (v *Viper) MarkSensitive(paths ...string) {
	if v.sensitivePaths == nil {
		v.sensitivePaths = make(map[string]struct{})
	}
	for _, path := range paths {
		v.sensitivePaths[strings.ToLower(path)] = struct{}{}
	}
}

// SetReferenceMaxDepth sets the maximum number of nested reference hops
// performed while resolving a single key. Non-positive values are ignored.
// Cached expansion results are discarded.
func (v *Viper) SetReferenceMaxDepth(depth int) {
	if depth <= 0 {
		return
	}
	v.refMaxDepth = depth
	v.invalidateRefCache()
}

func (v *Viper) newRefResolver() *refResolver {
	if v.refMaxDepth <= 0 {
		v.refMaxDepth = DefaultReferenceMaxDepth
	}
	if v.refCache == nil {
		v.refCache = make(map[string]*refCacheEntry)
	}
	return &refResolver{
		v:        v,
		maxDepth: v.refMaxDepth,
		memo:     make(map[string]*refEntry),
	}
}

// invalidateRefCache discards cached expansion results. It is called whenever
// a value-bearing register changes.
func (v *Viper) invalidateRefCache() {
	v.refCache = nil
}

func (v *Viper) isSensitivePath(path string) bool {
	for marked := range v.sensitivePaths {
		if marked == path || strings.HasPrefix(path, marked+v.keyDelim) {
			return true
		}
	}
	return false
}

func (r *refResolver) resolve(key string) (any, ReferenceError) {
	// Already expanded during this run.
	if e, ok := r.memo[key]; ok {
		if e.pending {
			return nil, ReferenceCycleError{Chain: r.closedLoop(key)}
		}
		return e.value, e.err
	}

	// A result cached from an earlier run still records dependencies so
	// sensitivity propagation and diagnostics stay complete.
	if c, ok := r.v.refCache[key]; ok {
		r.recordCached(key, c)
		return c.value, nil
	}

	if r.depth >= r.maxDepth {
		chain := append(slices.Clone(r.chain), key)
		return nil, ReferenceDepthError{Limit: r.maxDepth, Chain: chain}
	}

	e := &refEntry{path: key, pending: true}
	r.memo[key] = e
	r.order = append(r.order, key)

	r.chain = append(r.chain, key)
	r.depth++
	r.v.refResolveCount++
	raw := r.v.find(key, true)

	var refErr ReferenceError
	if raw == nil {
		refErr = ReferenceMissingError{Target: key, Chain: slices.Clone(r.chain)}
	} else {
		e.source = r.v.findSource(key)
		var value any
		value, refErr = r.expand(raw, e)
		if refErr == nil {
			e.value = value
		}
	}

	r.depth--
	r.chain = r.chain[:len(r.chain)-1]
	e.pending = false
	e.err = refErr
	e.sensitive = r.entrySensitive(e)

	if refErr == nil {
		r.v.refCache[key] = &refCacheEntry{
			value:     e.value,
			source:    e.source,
			sensitive: e.sensitive,
			deps:      slices.Clone(e.deps),
		}
	}

	return e.value, refErr
}

// closedLoop returns the chain segment that forms the loop, with the entry
// point repeated at the end.
func (r *refResolver) closedLoop(key string) []string {
	idx := slices.Index(r.chain, key)
	if idx < 0 {
		return []string{key, key}
	}
	return append(slices.Clone(r.chain[idx:]), key)
}

func (r *refResolver) recordCached(key string, c *refCacheEntry) {
	if _, ok := r.memo[key]; ok {
		return
	}
	e := &refEntry{
		path:      key,
		source:    c.source,
		value:     c.value,
		deps:      slices.Clone(c.deps),
		sensitive: c.sensitive,
	}
	r.memo[key] = e
	r.order = append(r.order, key)
	// Pull in transitive dependencies of cached entries as well.
	for _, dep := range c.deps {
		if dc, ok := r.v.refCache[dep]; ok {
			r.recordCached(dep, dc)
		}
	}
}

func (r *refResolver) entrySensitive(e *refEntry) bool {
	if r.v.isSensitivePath(e.path) {
		return true
	}
	for _, dep := range e.deps {
		if d, ok := r.memo[dep]; ok && d.sensitive {
			return true
		}
	}
	return false
}

func (r *refResolver) diagnostics() []ReferenceDiagnostic {
	order := slices.Clone(r.order)
	sort.Strings(order)
	seen := make(map[string]struct{}, len(order))
	out := make([]ReferenceDiagnostic, 0, len(order))
	for _, key := range order {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		e := r.memo[key]
		if e == nil {
			continue
		}
		deps := slices.Clone(e.deps)
		sort.Strings(deps)
		source := e.source
		if source == "" {
			// Missing or failed keys still name the attempted lookup layer.
			source = r.v.findSource(key)
		}
		sensitive := e.sensitive || r.v.isSensitivePath(key)
		if !sensitive {
			for _, dep := range deps {
				if d, ok := r.memo[dep]; ok && (d.sensitive || r.v.isSensitivePath(dep)) {
					sensitive = true
					break
				}
			}
		}
		out = append(out, ReferenceDiagnostic{
			Path:         key,
			Source:       source,
			Sensitive:    sensitive,
			Dependencies: deps,
		})
	}
	return out
}

// expand expands references inside one raw value selected by Viper's
// precedence rules.
func (r *refResolver) expand(raw any, e *refEntry) (any, ReferenceError) {
	switch val := raw.(type) {
	case string:
		return r.expandString(val, e)
	case map[string]any:
		return r.expandStringMap(val, e)
	case map[string]string:
		return r.expandStringStringMap(val, e)
	case map[any]any:
		return r.expandAnyMap(val, e)
	default:
		rv := reflect.ValueOf(raw)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			return r.expandSlice(rv, e)
		default:
			return raw, nil
		}
	}
}

func (r *refResolver) addDependency(e *refEntry, target string) {
	if !slices.Contains(e.deps, target) {
		e.deps = append(e.deps, target)
	}
}

func (r *refResolver) expandString(s string, e *refEntry) (any, ReferenceError) {
	tokens := parseReferenceString(s)
	hasRef := false
	for _, token := range tokens {
		if !token.literal {
			hasRef = true
			break
		}
	}
	if !hasRef {
		// No references: re-join the literal tokens so escaped sequences
		// collapse to their literal form.
		var b strings.Builder
		for _, token := range tokens {
			b.WriteString(token.text)
		}
		return b.String(), nil
	}

	// Whole-value reference: the string consists of exactly one reference, so
	// the referenced value keeps its original type (list, map, scalar, ...).
	if len(tokens) == 1 {
		target := tokens[0].text
		r.addDependency(e, target)
		return r.resolve(target)
	}

	// Interpolated reference: only scalar values can be rendered as text.
	var b strings.Builder
	for _, token := range tokens {
		if token.literal {
			b.WriteString(token.text)
			continue
		}
		target := token.text
		r.addDependency(e, target)
		value, refErr := r.resolve(target)
		if refErr != nil {
			return nil, refErr
		}
		if !isScalarValue(value) {
			return nil, ReferenceNonScalarError{
				Target: target,
				Chain:  append(slices.Clone(r.chain), target),
			}
		}
		b.WriteString(scalarToString(value))
	}
	return b.String(), nil
}

func (r *refResolver) expandStringMap(in map[string]any, e *refEntry) (map[string]any, ReferenceError) {
	out := make(map[string]any, len(in))
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, refErr := r.expand(in[key], e)
		if refErr != nil {
			return nil, refErr
		}
		out[key] = value
	}
	return out, nil
}

func (r *refResolver) expandStringStringMap(in map[string]string, e *refEntry) (map[string]string, ReferenceError) {
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, refErr := r.expandString(in[key], e)
		if refErr != nil {
			return nil, refErr
		}
		str, ok := value.(string)
		if !ok {
			return nil, ReferenceNonScalarError{
				Target: key,
				Chain:  append(slices.Clone(r.chain), key),
			}
		}
		out[key] = str
	}
	return out, nil
}

func (r *refResolver) expandAnyMap(in map[any]any, e *refEntry) (map[any]any, ReferenceError) {
	out := make(map[any]any, len(in))
	for key, value := range in {
		expanded, refErr := r.expand(value, e)
		if refErr != nil {
			return nil, refErr
		}
		out[key] = expanded
	}
	return out, nil
}

func (r *refResolver) expandSlice(rv reflect.Value, e *refEntry) ([]any, ReferenceError) {
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		value, refErr := r.expand(rv.Index(i).Interface(), e)
		if refErr != nil {
			return nil, refErr
		}
		out[i] = value
	}
	return out, nil
}

// isScalarValue reports whether value may be rendered inside an interpolated
// string. Maps and slices (and pointers to collections) are not scalars.
func isScalarValue(value any) bool {
	for value != nil {
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Ptr, reflect.Interface:
			if rv.IsNil() {
				return true
			}
			value = rv.Elem().Interface()
			continue
		case reflect.Map, reflect.Slice, reflect.Array:
			return false
		default:
			return true
		}
	}
	return true
}

// scalarToString renders a scalar value the same way Viper's typed getters
// would present it.
func scalarToString(value any) string {
	switch val := value.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case time.Time:
		return val.String()
	case time.Duration:
		return val.String()
	case bool:
		return strconv.FormatBool(val)
	case int:
		return strconv.FormatInt(int64(val), 10)
	case int8:
		return strconv.FormatInt(int64(val), 10)
	case int16:
		return strconv.FormatInt(int64(val), 10)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint8:
		return strconv.FormatUint(uint64(val), 10)
	case uint16:
		return strconv.FormatUint(uint64(val), 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case float32:
		return strconv.FormatFloat(float64(val), 'g', -1, 32)
	case float64:
		return strconv.FormatFloat(val, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// refToken is one piece of a parsed string: either literal text or a
// reference target.
type refToken struct {
	literal bool
	text    string
}

// parseReferenceString splits s into literal text and reference tokens. An
// escaped $$ immediately followed by an opening brace is returned as the
// literal text consisting of a dollar sign; the brace is then scanned as an
// ordinary character. A dollar sign that does not open a reference is kept
// verbatim.
func parseReferenceString(s string) []refToken {
	var tokens []refToken
	var literal strings.Builder
	flush := func() {
		if literal.Len() > 0 {
			tokens = append(tokens, refToken{literal: true, text: literal.String()})
			literal.Reset()
		}
	}

	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == '$' && s[i+1] == '$' && s[i+2] == '{' {
			flush()
			tokens = append(tokens, refToken{literal: true, text: refOpen})
			i += 3
			continue
		}
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			closeAt := strings.IndexByte(s[i+2:], '}')
			if closeAt < 0 {
				// Unterminated reference: the dollar sign is ordinary text.
				literal.WriteByte(s[i])
				i++
				continue
			}
			target := strings.TrimSpace(s[i+2 : i+2+closeAt])
			if target != "" {
				flush()
				tokens = append(tokens, refToken{literal: false, text: target})
				i = i + 2 + closeAt + 1
				continue
			}
		}
		literal.WriteByte(s[i])
		i++
	}
	if literal.Len() > 0 {
		tokens = append(tokens, refToken{literal: true, text: literal.String()})
	}
	return tokens
}

// findSource mirrors the precedence order of Viper.find and names the layer
// that supplies lcaseKey's value. It returns "unset" when no layer holds a
// value. Only path lookups are repeated; values are never inspected, so this
// is safe for sensitive configuration.
func (v *Viper) findSource(lcaseKey string) string {
	path := strings.Split(lcaseKey, v.keyDelim)
	nested := len(path) > 1

	if nested && v.isPathShadowedInDeepMap(path, castMapStringToMapInterface(v.aliases)) != "" {
		return sourceUnset
	}
	lcaseKey = v.realKey(lcaseKey)
	path = strings.Split(lcaseKey, v.keyDelim)
	nested = len(path) > 1

	if val := v.searchMap(v.override, path); val != nil {
		return sourceOverride
	}
	if nested && v.isPathShadowedInDeepMap(path, v.override) != "" {
		return sourceUnset
	}

	if flag, exists := v.pflags[lcaseKey]; exists && flag.HasChanged() {
		return sourceFlag
	}
	if nested && v.isPathShadowedInFlatMap(path, v.pflags) != "" {
		return sourceUnset
	}

	if v.automaticEnvApplied {
		envKey := strings.Join(append(v.parents, lcaseKey), ".")
		if _, ok := v.getEnv(v.mergeWithEnvPrefix(envKey)); ok {
			return sourceEnv
		}
		if nested && v.isPathShadowedInAutoEnv(path) != "" {
			return sourceUnset
		}
	}
	if envkeys, exists := v.env[lcaseKey]; exists {
		for _, envkey := range envkeys {
			if _, ok := v.getEnv(envkey); ok {
				return sourceEnv
			}
		}
	}
	if nested && v.isPathShadowedInFlatMap(path, v.env) != "" {
		return sourceUnset
	}

	if val := v.searchIndexableWithPathPrefixes(v.config, path); val != nil {
		return sourceConfig
	}
	if nested && v.isPathShadowedInDeepMap(path, v.config) != "" {
		return sourceUnset
	}

	if val := v.searchMap(v.kvstore, path); val != nil {
		return sourceKVStore
	}
	if nested && v.isPathShadowedInDeepMap(path, v.kvstore) != "" {
		return sourceUnset
	}

	if val := v.searchMap(v.defaults, path); val != nil {
		return sourceDefault
	}
	if nested && v.isPathShadowedInDeepMap(path, v.defaults) != "" {
		return sourceUnset
	}

	if _, exists := v.pflags[lcaseKey]; exists {
		return sourceFlagDefault
	}

	return sourceUnset
}
