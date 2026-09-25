// Copyright © 2014 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package viper

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

// DefaultIncludeMaxDepth is the default maximum number of nested include
// levels. The root configuration file is level 1.
const DefaultIncludeMaxDepth = 10

// DefaultIncludeMaxFiles is the default maximum number of configuration files
// (including the root file) that are read during a single load.
const DefaultIncludeMaxFiles = 64

// includeKey is the top-level configuration key that lists local files to
// include. It is stripped from the merged configuration.
const includeKey = "include"

// ExperimentalInclude enables local configuration file includes.
//
// When enabled, a configuration file may declare a top-level "include" key
// containing a list of relative paths. Each included file is merged into the
// configuration before the file that declares the include, in declaration
// order. The same file is only read once per load, while repeats along a
// single recursive chain are reported as a cycle.
//
// Includes are resolved relative to the file that declares them. The
// "include" key itself never becomes part of the loaded configuration.
func ExperimentalInclude() Option {
	return optionFunc(func(v *Viper) {
		v.experimentalInclude = true
	})
}

// IncludeLimits configures the maximum include depth and the maximum number of
// files read during a single load. Zero or negative values fall back to the
// defaults ([DefaultIncludeMaxDepth] and [DefaultIncludeMaxFiles]).
//
// This option only takes effect together with [ExperimentalInclude].
func IncludeLimits(maxDepth, maxFiles int) Option {
	return optionFunc(func(v *Viper) {
		if maxDepth > 0 {
			v.includeMaxDepth = maxDepth
		}

		if maxFiles > 0 {
			v.includeMaxFiles = maxFiles
		}
	})
}

// IncludeError wraps an error that occurred while resolving local includes.
// Chain lists the files from the root configuration file down to (and
// including) the file that caused the error. It can be used to reconstruct
// the full include chain that led to the failure.
type IncludeError struct {
	// Chain is the ordered list of files from the root to the failing file.
	Chain []string

	err error
}

func (e IncludeError) Error() string {
	return fmt.Sprintf("include %s: %s", strings.Join(e.Chain, " -> "), e.err)
}

// Unwrap returns the underlying error.
func (e IncludeError) Unwrap() error {
	return e.err
}

// IncludeCycleError denotes an include cycle detected along a single
// recursive include chain. A file referenced again by a sibling is parsed
// only once and does not produce this error.
type IncludeCycleError struct {
	path string
}

func (e IncludeCycleError) Error() string {
	return fmt.Sprintf("include cycle detected at %s", e.path)
}

// IncludeDepthError denotes that the maximum include depth was exceeded.
type IncludeDepthError struct {
	maxDepth int
}

func (e IncludeDepthError) Error() string {
	return fmt.Sprintf("maximum include depth of %d exceeded", e.maxDepth)
}

// IncludeFileCountError denotes that the maximum number of files for a single
// load was exceeded.
type IncludeFileCountError struct {
	maxFiles int
}

func (e IncludeFileCountError) Error() string {
	return fmt.Sprintf("maximum number of included files %d exceeded", e.maxFiles)
}

// IncludeKeyConflictError denotes that a single file declares the include key
// more than once with different casing, for example both "include" and
// "Include". Viper keys are case-insensitive, so the intent is ambiguous.
type IncludeKeyConflictError struct {
	path string
	keys []string
}

func (e IncludeKeyConflictError) Error() string {
	return fmt.Sprintf("conflicting include keys %v in %s", e.keys, e.path)
}

// includeResolver resolves and merges local includes for a single load.
type includeResolver struct {
	v *Viper

	maxDepth int
	maxFiles int

	// files counts every unique file encountered during the load.
	files int

	// seen contains the canonical paths of files that have already been read.
	// The value is the file's fully merged configuration.
	seen map[string]map[string]any

	// active contains the canonical paths currently being resolved along one
	// recursive chain, used for cycle detection.
	active []string
}

// readConfigWithIncludes reads the root configuration file and all of its
// includes and returns the merged configuration. It does not mutate the
// Viper instance, so callers can keep the previous configuration when an
// error occurs.
func (v *Viper) readConfigWithIncludes(filename string) (map[string]any, error) {
	r := &includeResolver{
		v:        v,
		maxDepth: v.includeMaxDepth,
		maxFiles: v.includeMaxFiles,
		seen:     make(map[string]map[string]any),
	}

	return r.load(filename, nil)
}

// load reads and merges filename. chain holds the declaring files above the
// current file (it does not contain filename yet).
func (r *includeResolver) load(filename string, chain []string) (config map[string]any, err error) {
	// The canonical form is used for dedup and cycle detection. Relative
	// paths are cleaned (including ".." segments) without turning them into
	// working-directory dependent absolute paths, because includes are always
	// resolved relative to their declaring file.
	canonical := filepath.Clean(filename)

	depth := len(chain) + 1
	if depth > r.maxDepth {
		return nil, IncludeError{
			Chain: appendChain(chain, canonical),
			err:   IncludeDepthError{maxDepth: r.maxDepth},
		}
	}

	for _, active := range r.active {
		if active == canonical {
			return nil, IncludeError{
				Chain: appendChain(chain, canonical),
				err:   IncludeCycleError{path: canonical},
			}
		}
	}

	// A file referenced again by a sibling (or another already completed chain)
	// is only parsed once: reuse the result of the first load. A copy is
	// returned so consumers can merge it without sharing nested maps.
	if merged, ok := r.seen[canonical]; ok {
		return copyAndInsensitiviseMap(merged), nil
	}

	if r.files >= r.maxFiles {
		return nil, IncludeError{
			Chain: appendChain(chain, canonical),
			err:   IncludeFileCountError{maxFiles: r.maxFiles},
		}
	}

	r.files++

	format, err := r.formatFor(canonical)
	if err != nil {
		return nil, IncludeError{Chain: appendChain(chain, canonical), err: err}
	}

	data, err := afero.ReadFile(r.v.fs, canonical)
	if err != nil {
		return nil, IncludeError{Chain: appendChain(chain, canonical), err: err}
	}

	config = make(map[string]any)

	if err := r.v.decodeConfigBytes(bytes.NewReader(data), format, config, false); err != nil {
		return nil, IncludeError{Chain: appendChain(chain, canonical), err: err}
	}

	includes, includeDeclaration, err := extractIncludes(canonical, config)
	if err != nil {
		return nil, IncludeError{Chain: appendChain(chain, canonical), err: err}
	}

	if includeDeclaration != "" {
		delete(config, includeDeclaration)
	}

	insensitiviseMap(config)

	// Record the file as active while resolving its includes so that repeats
	// along this chain are detected as cycles.
	r.active = append(r.active, canonical)

	defer func() {
		r.active = r.active[:len(r.active)-1]
	}()

	childChain := appendChain(chain, canonical)

	// Includes are merged first in declaration order, followed by the
	// declaring file itself, which gives the current file the highest
	// priority within this subtree.
	merged := make(map[string]any)

	for _, include := range includes {
		includePath := include
		if !filepath.IsAbs(includePath) {
			includePath = filepath.Join(filepath.Dir(canonical), includePath)
		}

		includePath = filepath.Clean(includePath)

		included, err := r.load(includePath, childChain)
		if err != nil {
			return nil, err
		}

		mergeMaps(included, merged, nil)
	}

	mergeMaps(copyAndInsensitiviseMap(config), merged, nil)

	// Cache the complete subtree (includes + own content). It is a pure
	// function of this file and its descendants, so siblings can safely reuse
	// it without re-reading the file; copies handed out by load keep nested
	// maps isolated between consumers.
	r.seen[canonical] = merged

	return merged, nil
}

// formatFor determines the config format of filename. The extension wins;
// otherwise the explicitly configured config type is used, which mirrors how
// extension-less root config files are handled.
func (r *includeResolver) formatFor(filename string) (string, error) {
	format := strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))
	if format != "" {
		if !isSupportedExt(format) {
			return "", UnsupportedConfigError(format)
		}

		return format, nil
	}

	format = strings.ToLower(r.v.configType)
	if format == "" {
		return "", fmt.Errorf("cannot decode configuration %q: unable to determine config type", filename)
	}

	if !isSupportedExt(format) {
		return "", UnsupportedConfigError(format)
	}

	return format, nil
}

func isSupportedExt(format string) bool {
	for _, ext := range SupportedExts {
		if ext == format {
			return true
		}
	}

	return false
}

// extractIncludes returns the declared includes of a freshly decoded file and
// the exact key name under which they were declared. It detects multiple
// case-variant declarations of the include key and validates that every entry
// is a string. The map is not mutated.
func extractIncludes(path string, config map[string]any) (includes []string, declaration string, err error) {
	var declarations []string
	var value any

	for key, raw := range config {
		if strings.EqualFold(key, includeKey) {
			declarations = append(declarations, key)
			value = raw
		}
	}

	switch len(declarations) {
	case 0:
		return nil, "", nil
	case 1:
		// A single declaration (regardless of casing) is accepted.
	default:
		return nil, "", IncludeKeyConflictError{path: path, keys: declarations}
	}

	entries, ok := value.([]any)
	if !ok {
		return nil, "", fmt.Errorf("the %q key in %s must be a list of file paths", includeKey, path)
	}

	includes = make([]string, 0, len(entries))

	for i, entry := range entries {
		include, ok := entry.(string)
		if !ok {
			return nil, "", fmt.Errorf("the %q key in %s must contain only file paths: entry #%d is %T", includeKey, path, i, entry)
		}

		includes = append(includes, include)
	}

	return includes, declarations[0], nil
}

func appendChain(chain []string, path string) []string {
	result := make([]string, 0, len(chain)+1)
	result = append(result, chain...)

	return append(result, path)
}
