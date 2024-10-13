// Copyright (c) 2019 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

package goartifacts

import (
	"fmt"
	"io/fs"
	"log"
	"regexp"
	"runtime"
	"strings"

	"github.com/forensicanalysis/fsdoublestar"
)

const windows = "windows"

// ExpandSource expands a single artifact definition source by expanding its
// paths or keys.
func ExpandSource(source Source, collector ArtifactCollector) Source { //nolint:cyclop,funlen
	replacer := strings.NewReplacer("\\", "/", "/", "\\")

	switch source.Type {
	case SourceType.File, SourceType.Directory, SourceType.Path:
		// expand paths
		var expandedPaths []string

		for _, path := range source.Attributes.Paths {
			if source.Attributes.Separator == "\\" {
				path = strings.Replace(path, "\\", "/", -1)
			}

			paths, err := expandPath(collector.FS(), path, collector.Prefixes(), collector)
			if err != nil {
				log.Println(err)

				continue
			}

			expandedPaths = append(expandedPaths, paths...)
		}

		source.Attributes.Paths = expandedPaths
	case SourceType.RegistryKey:
		// expand keys
		var expandKeys []string

		for _, key := range source.Attributes.Keys {
			key = "/" + replacer.Replace(key)

			keys, err := expandKey(key, collector)
			if err != nil {
				log.Println(err)

				continue
			}

			expandKeys = append(expandKeys, keys...)
		}

		source.Attributes.Keys = expandKeys
	case SourceType.RegistryValue:
		// expand key value pairs
		var expandKeyValuePairs []KeyValuePair

		for _, keyValuePair := range source.Attributes.KeyValuePairs {
			key := "/" + replacer.Replace(keyValuePair.Key)

			keys, err := expandKey(key, collector)
			if err != nil {
				log.Println(err)

				continue
			}

			for _, expandKey := range keys {
				expandKeyValuePairs = append(expandKeyValuePairs, KeyValuePair{Key: expandKey, Value: keyValuePair.Value})
			}
		}

		source.Attributes.KeyValuePairs = expandKeyValuePairs
	}

	return source
}

func expandArtifactGroup(names []string, definitions map[string]ArtifactDefinition) map[string]ArtifactDefinition { //nolint:cyclop
	selected := map[string]ArtifactDefinition{}

	for _, name := range names {
		artifact, ok := definitions[name]
		if !ok {
			log.Printf("Artifact Definition %s not found", name)

			continue
		}

		if !IsOSArtifactDefinition(runtime.GOOS, artifact.SupportedOs) {
			continue
		}

		onlyGroup := true

		for _, source := range artifact.Sources {
			if source.Type == SourceType.ArtifactGroup {
				if IsOSArtifactDefinition(runtime.GOOS, source.SupportedOs) {
					for subName, subArtifact := range expandArtifactGroup(source.Attributes.Names, definitions) {
						selected[subName] = subArtifact
					}
				}
			} else {
				onlyGroup = false
			}
		}

		if !onlyGroup {
			var sources []Source

			for _, source := range artifact.Sources {
				if IsOSArtifactDefinition(runtime.GOOS, source.SupportedOs) {
					sources = append(sources, source)
				}
			}

			artifact.Sources = sources

			selected[artifact.Name] = artifact
		}
	}

	return selected
}

func isLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func toForensicPath(name string, prefixes []string) ([]string, error) { //nolint:cyclop
	if name[0] == '/' {
		name = name[1:]
	}

	if runtime.GOOS == windows {
		name = strings.Replace(name, `\`, "/", -1)
		if name[0] == '/' {
			name = name[1:]
		}

		switch {
		case len(name) == 0:
			return []string{"."}, nil
		case len(name) == 1:
			switch {
			case name[0] == '/':
				if len(prefixes) > 0 {
					return prefixes, nil
				}

				return []string{"."}, nil
			case isLetter(name[0]):
				return []string{name}, nil
			default:
				return nil, fmt.Errorf("invalid path: %s", name)
			}
		case name[1] == ':':
			return []string{name[:1] + name[2:]}, nil
		case isLetter(name[0]) && (len(name) == 1 || name[1] == '/'):
			return []string{name}, nil
		case len(prefixes) > 0:
			var names []string
			for _, prefix := range prefixes {
				names = append(names, fmt.Sprintf("%s/%s", prefix, name))
			}

			return names, nil
		default:
			return []string{name}, nil
		}
	}

	return []string{name}, nil
}

func expandPath(fs fs.FS, syspath string, prefixes []string, collector ArtifactCollector) ([]string, error) {
	// expand vars
	variablePaths, err := recursiveResolve(syspath, collector)
	if err != nil {
		return nil, err
	}

	if len(variablePaths) == 0 {
		return nil, nil
	}

	var partitionPaths []string

	for _, variablePath := range variablePaths {
		forensicPaths, err := toForensicPath(variablePath, prefixes)
		if err != nil {
			return nil, err
		}

		partitionPaths = append(partitionPaths, forensicPaths...)
	}

	addedPaths := make(map[string]bool)

	// unglob and unique paths
	var uniquePaths []string

	for _, expandedPath := range partitionPaths {
		expandedPath = strings.Replace(expandedPath, "{", `\{`, -1)
		expandedPath = strings.Replace(expandedPath, "}", `\}`, -1)

		unglobedPaths, err := fsdoublestar.Glob(fs, expandedPath)
		if err != nil {
			log.Println(err)

			continue
		}

		for _, unglobedPath := range unglobedPaths {
			// TODO: this also removes files with the same name in different cases in case sensitive filesystems
			if _, ok := addedPaths[strings.ToLower(unglobedPath)]; !ok {
				addedPaths[strings.ToLower(unglobedPath)] = true

				uniquePaths = append(uniquePaths, unglobedPath)
			}
		}
	}

	return uniquePaths, nil
}

func expandKey(path string, collector ArtifactCollector) ([]string, error) {
	if runtime.GOOS == windows {
		return expandPath(collector.Registry(), path, nil, collector)
	}

	return []string{}, nil
}

func recursiveResolve(s string, collector ArtifactCollector) ([]string, error) {
	re := regexp.MustCompile(`%?%(.*?)%?%`)
	matches := re.FindAllStringSubmatch(s, -1)

	if len(matches) > 0 {
		var replacedParameters []string

		for _, match := range matches {
			resolves, err := collector.Resolve(match[1])
			if err != nil {
				return nil, err
			}

			replacedParameters = append(replacedParameters, replaces(re, s, resolves)...)
		}

		var results []string

		for _, result := range replacedParameters {
			childResults, err := recursiveResolve(result, collector)
			if err != nil {
				return nil, err
			}

			results = append(results, childResults...)
		}

		return results, nil
	}

	return []string{s}, nil
}

func replaces(regex *regexp.Regexp, s string, news []string) (ss []string) {
	for _, newString := range news {
		ss = append(ss, regex.ReplaceAllString(s, newString))
	}

	return
}
