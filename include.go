package viper

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/afero"
)

const (
	// DefaultIncludeKey is the configuration key used to declare includes.
	DefaultIncludeKey = "include"

	// DefaultIncludeMaxDepth is the default maximum length of an include
	// chain, counting the root configuration file as depth 1.
	DefaultIncludeMaxDepth = 16

	// DefaultIncludeMaxFiles is the default maximum number of files parsed
	// during a single load, counting the root configuration file.
	DefaultIncludeMaxFiles = 64
)

var (
	// ErrIncludeMaxDepth is returned (wrapped in an [IncludeError]) when an
	// include chain grows deeper than the configured maximum depth.
	ErrIncludeMaxDepth = errors.New("maximum include depth exceeded")

	// ErrIncludeMaxFiles is returned (wrapped in an [IncludeError]) when a
	// single load parses more files than the configured maximum.
	ErrIncludeMaxFiles = errors.New("maximum include file count exceeded")
)

// IncludeCycleError denotes a configuration file including itself, directly
// or transitively, within a single include chain.
type IncludeCycleError struct {
	// Chain holds the canonical paths of the include chain, ending with the
	// file that closes the cycle.
	Chain []string
}

// Error returns the formatted error, including the full include chain.
func (e IncludeCycleError) Error() string {
	return fmt.Sprintf("include cycle detected: %s", strings.Join(e.Chain, " -> "))
}

// IncludeError denotes a failure while resolving included configuration
// files. It carries the full include chain from the root configuration file
// down to the file that caused the failure.
type IncludeError struct {
	// Chain holds the canonical paths of the include chain, ending with the
	// file that failed to load.
	Chain []string

	// Err is the underlying failure.
	Err error
}

// Error returns the formatted error, including the full include chain.
func (e IncludeError) Error() string {
	return fmt.Sprintf("include chain %s: %s", strings.Join(e.Chain, " -> "), e.Err.Error())
}

// Unwrap returns the underlying failure.
func (e IncludeError) Unwrap() error {
	return e.Err
}

// WithIncludes enables the local include loader.
//
// When enabled, a configuration file may declare a list of other files to
// include under the include key ("include" by default, see [IncludeKey]).
// Included files are merged first, in declaration order, and the declaring
// file is merged last, so its values take precedence. Values set through
// environment variables, flags or Set keep their usual, higher priority.
//
// Include paths are resolved relative to the file that declares them. The
// include key itself is consumed by the loader and never shows up in the
// resulting configuration.
func WithIncludes() Option {
	return optionFunc(func(v *Viper) {
		v.includesEnabled = true
	})
}

// IncludeKey sets the configuration key used to declare includes.
// The key may be nested using the configured key delimiter.
// By default it's "include".
func IncludeKey(key string) Option {
	return optionFunc(func(v *Viper) {
		if key == "" {
			return
		}

		v.includeKey = key
	})
}

// IncludeMaxDepth sets the maximum length of an include chain, counting the
// root configuration file as depth 1. Values smaller than 1 are ignored.
// By default it's [DefaultIncludeMaxDepth].
func IncludeMaxDepth(depth int) Option {
	return optionFunc(func(v *Viper) {
		if depth < 1 {
			return
		}

		v.includeMaxDepth = depth
	})
}

// IncludeMaxFiles sets the maximum number of files parsed during a single
// load, counting the root configuration file. Values smaller than 1 are
// ignored. By default it's [DefaultIncludeMaxFiles].
func IncludeMaxFiles(max int) Option {
	return optionFunc(func(v *Viper) {
		if max < 1 {
			return
		}

		v.includeMaxFiles = max
	})
}

// includeState tracks a single load of a configuration file and its
// includes.
type includeState struct {
	// chain holds the canonical paths of the files currently being resolved,
	// from the root configuration file down to the current one.
	chain []string

	// cache maps canonical paths to the fully merged configuration of files
	// that have already been resolved during this load. It ensures a file
	// referenced by multiple siblings is only read and parsed once.
	cache map[string]map[string]any

	// files counts the files parsed during this load.
	files int
}

// readConfigWithIncludes parses the root configuration file and recursively
// resolves its includes. The returned map is only assigned to the live
// configuration by the caller once the whole file layer parsed successfully.
func (v *Viper) readConfigWithIncludes(filename string, data []byte) (map[string]any, error) {
	state := &includeState{
		cache: make(map[string]map[string]any),
	}

	return v.resolveIncludes(state, filename, data, v.getConfigType())
}

// resolveIncludes parses a single configuration file, merges the
// configurations of the files it includes (in declaration order) and finally
// merges the file's own values on top.
func (v *Viper) resolveIncludes(state *includeState, filename string, data []byte, format string) (map[string]any, error) {
	canonical := canonicalIncludePath(filename)

	if slices.Contains(state.chain, canonical) {
		return nil, IncludeCycleError{Chain: append(slices.Clone(state.chain), canonical)}
	}

	if len(state.chain)+1 > v.includeMaxDepth {
		return nil, IncludeError{
			Chain: append(slices.Clone(state.chain), canonical),
			Err:   ErrIncludeMaxDepth,
		}
	}

	state.files++
	if state.files > v.includeMaxFiles {
		return nil, IncludeError{
			Chain: append(slices.Clone(state.chain), canonical),
			Err:   ErrIncludeMaxFiles,
		}
	}

	raw := make(map[string]any)
	if err := v.unmarshalBytes(format, data, raw); err != nil {
		return nil, IncludeError{
			Chain: append(slices.Clone(state.chain), canonical),
			Err:   err,
		}
	}

	includes, err := v.extractIncludes(raw)
	if err != nil {
		return nil, IncludeError{
			Chain: append(slices.Clone(state.chain), canonical),
			Err:   err,
		}
	}

	state.chain = append(state.chain, canonical)
	defer func() {
		state.chain = state.chain[:len(state.chain)-1]
	}()

	merged := make(map[string]any)
	for _, include := range includes {
		child := include
		if !filepath.IsAbs(child) {
			child = filepath.Join(filepath.Dir(filename), child)
		}

		childConfig, err := v.loadInclude(state, child)
		if err != nil {
			return nil, err
		}

		mergeMaps(childConfig, merged, nil)
	}

	// The declaring file takes precedence over the files it includes.
	mergeMaps(raw, merged, nil)

	state.cache[canonical] = merged

	return merged, nil
}

// loadInclude reads and resolves a single included file. Files already
// resolved during this load are served from the cache, so a shared file is
// only read from disk once per load.
func (v *Viper) loadInclude(state *includeState, filename string) (map[string]any, error) {
	canonical := canonicalIncludePath(filename)

	if cached, ok := state.cache[canonical]; ok {
		return cached, nil
	}

	v.logger.Debug("reading included file", "file", filename)

	data, err := afero.ReadFile(v.fs, filename)
	if err != nil {
		return nil, IncludeError{
			Chain: append(slices.Clone(state.chain), canonical),
			Err:   err,
		}
	}

	format := strings.TrimPrefix(strings.ToLower(filepath.Ext(filename)), ".")

	return v.resolveIncludes(state, filename, data, format)
}

// extractIncludes removes the include directive from the parsed
// configuration and returns the declared include paths in declaration order.
func (v *Viper) extractIncludes(raw map[string]any) ([]string, error) {
	if v.includeKey == "" {
		return nil, nil
	}

	// Keys have been insensitivised while decoding, so look the directive up
	// in lower case, honoring the configured key delimiter.
	parts := strings.Split(strings.ToLower(v.includeKey), v.keyDelim)

	current := raw
	for i, part := range parts {
		value, ok := current[part]
		if !ok {
			return nil, nil
		}

		if i == len(parts)-1 {
			delete(current, part)

			return includePaths(value)
		}

		nested, ok := value.(map[string]any)
		if !ok {
			return nil, nil
		}

		current = nested
	}

	return nil, nil
}

// includePaths converts an include directive into a list of paths.
func includePaths(value any) ([]string, error) {
	switch value := value.(type) {
	case string:
		return []string{value}, nil
	case []string:
		return value, nil
	case []any:
		paths := make([]string, 0, len(value))
		for _, item := range value {
			path, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid include directive: expected a string or a list of strings, got %T", item)
			}

			paths = append(paths, path)
		}

		return paths, nil
	default:
		return nil, fmt.Errorf("invalid include directive: expected a string or a list of strings, got %T", value)
	}
}

// canonicalIncludePath returns the canonical form of a file path used for
// cycle detection and caching.
func canonicalIncludePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}

	return filepath.Clean(abs)
}
