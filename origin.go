package viper

import (
	"strings"
)

// Source identifies the configuration layer that actually won the lookup
// performed by [Viper.GetWithOrigin].
//
// The returned Source matches the value returned by [Viper.Get] for the same
// key: it is recorded while the single layered lookup walks the sources in
// priority order, it is never reconstructed by scanning the merged result of
// [Viper.AllSettings].
type Source string

const (
	// SourceNone is reported when no layer holds a value for the key.
	SourceNone Source = ""

	// SourceDefault is the layer of values registered with SetDefault.
	SourceDefault Source = "default"

	// SourceKVPStore is the remote key/value store layer.
	SourceKVPStore Source = "kvstore"

	// SourceFile is the layer populated by reading a configuration file.
	SourceFile Source = "file"

	// SourceEnv is the environment variable layer.
	SourceEnv Source = "env"

	// SourceFlag is the bound command line flag layer. A flag explicitly
	// provided on the command line outranks environment, file and defaults;
	// a bound flag that was not provided only contributes its own default
	// value as a last chance, after the explicit default layer.
	SourceFlag Source = "flag"

	// SourceOverride is the explicit override layer populated by Set.
	SourceOverride Source = "override"
)

// GetOption configures a call to [Viper.GetWithOrigin].
type GetOption interface {
	applyGet(*getOptions)
}

type getOptionFunc func(*getOptions)

func (fn getOptionFunc) applyGet(o *getOptions) { fn(o) }

type getOptions struct {
	// sensitive omits the winning value from the result. The value is still
	// looked up exactly once (so existence and origin are accurate), but it
	// is never returned to the caller.
	sensitive bool
}

// GetSensitive marks a [Viper.GetWithOrigin] lookup as sensitive: the winning
// value is deliberately not returned, only whether the key exists and which
// Source it came from. Use it for secrets (passwords, tokens, ...) so the raw
// value cannot accidentally be logged or otherwise leaked.
func GetSensitive() GetOption {
	return getOptionFunc(func(o *getOptions) {
		o.sensitive = true
	})
}

// GetWithOrigin can retrieve any value given the key to use together with the
// Source that actually provided it.
//
// Get is case-insensitive for a key. Viper checks the layers in the following
// order and the first layer that holds a reachable value wins:
//
//	override, flag, env, config file, key/value store, default
//
// The returned value is the exact same effective value [Viper.Get] would have
// returned (including type inference driven by SetTypeByDefaultValue) and the
// returned Source identifies that value's layer. A single layered lookup is
// performed; the origin is observed during the lookup and is not inferred from
// the merged result of [Viper.AllSettings].
//
// Key aliases follow the same rules as [Viper.Get]: the alias is resolved to
// its real key first and the lookup then proceeds with the real key in every
// layer, so the reported origin is the origin of the aliased key.
//
// Nested keys can be affected by parent replacement (shadowing): if a
// higher-priority layer holds a non-map value for a parent path, that value
// replaces the entire subtree and lower-priority layers cannot contribute any
// child. In that case Get returns nil for the child and GetWithOrigin reports
// exists == false together with the Source of the parent value that replaced
// the subtree, so the actual deciding layer can be located.
//
// Environment variables that are set but empty are ignored by default for
// backward compatibility, so the lookup falls through to the next layer; the
// origin therefore does not report [SourceEnv] for them. Calling
// AllowEmptyEnv(true) changes that policy: empty environment variables are
// considered valid values, they win as [SourceEnv] (with an empty string as
// the value) and lower-priority layers are no longer consulted.
//
// When the key exists in no layer, GetWithOrigin returns a nil value,
// [SourceNone] and false.
//
// With [GetSensitive], the winning value is never returned (nil takes its
// place) while exists and the Source remain accurate; this is useful for
// secret values that must not leak into logs or output.
func GetWithOrigin(key string, opts ...GetOption) (any, Source, bool) {
	return v.GetWithOrigin(key, opts...)
}

// GetWithOrigin retrieves the value associated with the key together with the
// Source that actually provided it. See the package-level GetWithOrigin
// documentation for precedence, alias, nested shadowing, empty environment
// variable and sensitive lookup semantics.
func (v *Viper) GetWithOrigin(key string, opts ...GetOption) (any, Source, bool) {
	options := getOptions{}
	for _, opt := range opts {
		opt.applyGet(&options)
	}

	lcaseKey := strings.ToLower(key)

	// A single layered lookup produces both the effective value and its
	// origin: the origin is observed during the lookup, never reconstructed
	// from AllSettings afterwards.
	val, origin, exists := v.findWithOrigin(lcaseKey, true)

	if !exists {
		// No reachable value. A nested key shadowed by a non-map parent value
		// still reports that parent's layer: that is the source which replaced
		// the subtree. A lookup that reached no layer at all reports
		// SourceNone (the zero Source returned by findWithOrigin).
		return nil, origin, false
	}

	// Same effective value Get() returns, including type inference driven by
	// SetTypeByDefaultValue, via the shared coercion helper.
	val = v.coerceByDefaultValue(lcaseKey, val)

	if options.sensitive {
		// Sensitive lookup: report presence and origin only, never the value.
		return nil, origin, true
	}

	return val, origin, true
}
