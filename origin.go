// Copyright © 2024 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"strings"
	"time"

	"github.com/spf13/cast"
)

// Origin identifies the configuration layer that provided the value for a
// key (or that prevents a value from being seen, in the case of shadowing).
//
// Viper resolves keys in the following priority order (lowest to highest):
// default, key/value store, config file, environment variable, flag, and
// explicit override. The Origin reported by GetWithOrigin is the layer that
// actually won.
type Origin uint8

const (
	// OriginAbsent means the key has no value in any configuration layer.
	OriginAbsent Origin = iota

	// OriginDefault means the value was supplied via SetDefault.
	OriginDefault

	// OriginKVStore means the value came from a remote key/value store.
	OriginKVStore

	// OriginConfig means the value came from a configuration file.
	OriginConfig

	// OriginEnv means the value came from an environment variable.
	OriginEnv

	// OriginFlag means the value came from a bound pflag.
	OriginFlag

	// OriginOverride means the value was supplied via Set.
	OriginOverride
)

// String returns a short, human-readable name for the origin.
func (o Origin) String() string {
	switch o {
	case OriginDefault:
		return "default"
	case OriginKVStore:
		return "kvstore"
	case OriginConfig:
		return "config"
	case OriginEnv:
		return "env"
	case OriginFlag:
		return "flag"
	case OriginOverride:
		return "override"
	default:
		return "absent"
	}
}

// GetWithOriginOption configures a GetWithOrigin call.
type GetWithOriginOption func(*getWithOriginOptions)

type getWithOriginOptions struct {
	sensitive bool
}

// WithSensitive marks the requested key as sensitive for the duration of the
// call. The value is then withheld and only its existence and origin are
// reported. This is useful for secrets such as passwords, tokens or keys that
// should not be logged or otherwise exposed.
func WithSensitive() GetWithOriginOption {
	return func(o *getWithOriginOptions) {
		o.sensitive = true
	}
}

// GetWithOrigin retrieves the value associated with key and reports the
// configuration layer it came from.
//
// It returns the effective value (identical to what Get returns), the winning
// Origin, and whether the key exists in any layer. When the key is marked
// sensitive with WithSensitive, the value is withheld: only existence and
// origin are returned.
//
// The origin is recorded while the value is looked up. It is not inferred by
// scanning the merged AllSettings() map afterwards, so nested shadowing (a
// parent key in a higher-priority layer hiding a nested key in a lower one)
// is reported against the layer that actually causes it.
func (v *Viper) GetWithOrigin(key string, opts ...GetWithOriginOption) (value any, origin Origin, exists bool) {
	options := getWithOriginOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	lcaseKey := strings.ToLower(key)
	val, origin := v.findWithOrigin(lcaseKey, true)
	if val == nil {
		return nil, origin, false
	}

	if v.typeByDefValue {
		val = v.inferTypeByDefaultValue(lcaseKey, val)
	}

	if options.sensitive {
		// Withhold the actual value; report only existence and origin.
		return nil, origin, true
	}

	return val, origin, true
}

// GetWithOrigin retrieves the value associated with key and reports the
// configuration layer it came from. See Viper.GetWithOrigin for details.
func GetWithOrigin(key string, opts ...GetWithOriginOption) (value any, origin Origin, exists bool) {
	return v.GetWithOrigin(key, opts...)
}

// inferTypeByDefaultValue reproduces Get's typeByDefValue behavior: when
// enabled, the returned value is coerced to the type of the key's default
// value (if any).
func (v *Viper) inferTypeByDefaultValue(lcaseKey string, val any) any {
	valType := val
	path := strings.Split(lcaseKey, v.keyDelim)
	defVal := v.searchMap(v.defaults, path)
	if defVal != nil {
		valType = defVal
	}

	switch valType.(type) {
	case bool:
		return cast.ToBool(val)
	case string:
		return cast.ToString(val)
	case int32, int16, int8, int:
		return cast.ToInt(val)
	case uint:
		return cast.ToUint(val)
	case uint32:
		return cast.ToUint32(val)
	case uint64:
		return cast.ToUint64(val)
	case int64:
		return cast.ToInt64(val)
	case float64, float32:
		return cast.ToFloat64(val)
	case time.Time:
		return cast.ToTime(val)
	case time.Duration:
		return cast.ToDuration(val)
	case []string:
		return cast.ToStringSlice(val)
	case []int:
		return cast.ToIntSlice(val)
	case []time.Duration:
		return cast.ToDurationSlice(val)
	}

	return val
}

// findWithOrigin mirrors find but additionally records the layer that provided
// the returned value (or that shadows it). It performs a single traversal of
// the configuration layers; the origin is captured at the point where the
// value is found, so it never has to be reverse-engineered from AllSettings.
func (v *Viper) findWithOrigin(lcaseKey string, flagDefault bool) (any, Origin) {
	var (
		val    any
		exists bool
		path   = strings.Split(lcaseKey, v.keyDelim)
		nested = len(path) > 1
	)

	// compute the path through the nested maps to the nested value
	if nested && v.isPathShadowedInDeepMap(path, castMapStringToMapInterface(v.aliases)) != "" {
		return nil, OriginAbsent
	}

	// if the requested key is an alias, then return the proper key
	lcaseKey = v.realKey(lcaseKey)
	path = strings.Split(lcaseKey, v.keyDelim)
	nested = len(path) > 1

	// Set() override first
	val = v.searchMap(v.override, path)
	if val != nil {
		return val, OriginOverride
	}
	if nested && v.isPathShadowedInDeepMap(path, v.override) != "" {
		return nil, OriginOverride
	}

	// PFlag override next
	flag, exists := v.pflags[lcaseKey]
	if exists && flag.HasChanged() {
		return flagValueAs(flag), OriginFlag
	}
	if nested && v.isPathShadowedInFlatMap(path, v.pflags) != "" {
		return nil, OriginFlag
	}

	// Env override next
	if v.automaticEnvApplied {
		envKey := strings.Join(append(v.parents, lcaseKey), ".")
		// even if it hasn't been registered, if automaticEnv is used,
		// check any Get request
		if val, ok := v.getEnv(v.mergeWithEnvPrefix(envKey)); ok {
			return val, OriginEnv
		}
		if nested && v.isPathShadowedInAutoEnv(path) != "" {
			return nil, OriginEnv
		}
	}
	envkeys, exists := v.env[lcaseKey]
	if exists {
		for _, envkey := range envkeys {
			if val, ok := v.getEnv(envkey); ok {
				return val, OriginEnv
			}
		}
	}
	if nested && v.isPathShadowedInFlatMap(path, v.env) != "" {
		return nil, OriginEnv
	}

	// Config file next
	val = v.searchIndexableWithPathPrefixes(v.config, path)
	if val != nil {
		return val, OriginConfig
	}
	if nested && v.isPathShadowedInDeepMap(path, v.config) != "" {
		return nil, OriginConfig
	}

	// K/V store next
	val = v.searchMap(v.kvstore, path)
	if val != nil {
		return val, OriginKVStore
	}
	if nested && v.isPathShadowedInDeepMap(path, v.kvstore) != "" {
		return nil, OriginKVStore
	}

	// Default next
	val = v.searchMap(v.defaults, path)
	if val != nil {
		return val, OriginDefault
	}
	if nested && v.isPathShadowedInDeepMap(path, v.defaults) != "" {
		return nil, OriginDefault
	}

	if flagDefault {
		// last chance: if no value is found and a flag does exist for the key,
		// get the flag's default value even if the flag's value has not been set.
		if flag, exists := v.pflags[lcaseKey]; exists {
			return flagValueAs(flag), OriginFlag
		}
		// last item, no need to check shadowing
	}

	return nil, OriginAbsent
}

// flagValueAs converts a bound flag's current (or default) value into the
// same representation Get returns for that flag.
func flagValueAs(flag FlagValue) any {
	switch flag.ValueType() {
	case "int", "int8", "int16", "int32", "int64":
		return cast.ToInt(flag.ValueString())
	case "bool":
		return cast.ToBool(flag.ValueString())
	case "stringSlice", "stringArray":
		s := strings.TrimPrefix(flag.ValueString(), "[")
		s = strings.TrimSuffix(s, "]")
		res, _ := readAsCSV(s)
		return res
	case "boolSlice":
		s := strings.TrimPrefix(flag.ValueString(), "[")
		s = strings.TrimSuffix(s, "]")
		res, _ := readAsCSV(s)
		return cast.ToBoolSlice(res)
	case "intSlice":
		s := strings.TrimPrefix(flag.ValueString(), "[")
		s = strings.TrimSuffix(s, "]")
		res, _ := readAsCSV(s)
		return cast.ToIntSlice(res)
	case "uintSlice":
		s := strings.TrimPrefix(flag.ValueString(), "[")
		s = strings.TrimSuffix(s, "]")
		res, _ := readAsCSV(s)
		return cast.ToUintSlice(res)
	case "float64Slice":
		s := strings.TrimPrefix(flag.ValueString(), "[")
		s = strings.TrimSuffix(s, "]")
		res, _ := readAsCSV(s)
		return cast.ToFloat64Slice(res)
	case "durationSlice":
		s := strings.TrimPrefix(flag.ValueString(), "[")
		s = strings.TrimSuffix(s, "]")
		slice := strings.Split(s, ",")
		return cast.ToDurationSlice(slice)
	case "stringToString":
		return stringToStringConv(flag.ValueString())
	case "stringToInt":
		return stringToIntConv(flag.ValueString())
	default:
		return flag.ValueString()
	}
}
