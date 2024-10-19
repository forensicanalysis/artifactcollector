// Copyright (c) 2014-2019 Bob Matcuk
// Copyright (c) 2019-2020 Siemens AG
// Copyright (c) 2021 Jonas Plum
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
// Author(s): Bob Matcuk, Jonas Plum
//
// This code was adapted from
// https://github.com/bmatcuk/doublestar
// for use with forensic filesystems.

// Package doublestar provides a globing function for io/fs.
package doublestar

import (
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var doubleStarPattern = regexp.MustCompile(`^\*\*[0-9]*$`)

// ErrBadPattern indicates a pattern was malformed.
var ErrBadPattern = path.ErrBadPattern

// Split a path on the given separator, respecting escaping.
func splitPathOnSeparator(path string, separator rune) (ret []string) {
	idx := 0

	if separator == '\\' { //nolint:nestif
		// if the separator is '\\', then we can just split...
		ret = strings.Split(path, string(separator))
		idx = len(ret)
	} else {
		// otherwise, we need to be careful of situations where the separator was escaped
		cnt := strings.Count(path, string(separator))
		if cnt == 0 {
			return []string{path}
		}

		ret = make([]string, cnt+1)
		pathlen := len(path)
		separatorLen := utf8.RuneLen(separator)
		emptyEnd := false

		for start := 0; start < pathlen; {
			end := indexRuneWithEscaping(path[start:], separator)
			if end == -1 {
				emptyEnd = false
				end = pathlen
			} else {
				emptyEnd = true
				end += start
			}

			ret[idx] = path[start:end]
			start = end + separatorLen
			idx++
		}

		// If the last rune is a path separator, we need to append an empty string to
		// represent the last, empty path component. By default, the strings from
		// make([]string, ...) will be empty, so we just need to increment the count
		if emptyEnd {
			idx++
		}
	}

	return ret[:idx]
}

// Find the first index of a rune in a string,
// ignoring any times the rune is escaped using "\".
func indexRuneWithEscaping(s string, r rune) int {
	end := strings.IndexRune(s, r)
	if end == -1 {
		return -1
	}

	if end > 0 && s[end-1] == '\\' {
		start := end + utf8.RuneLen(r)
		end = indexRuneWithEscaping(s[start:], r)

		if end != -1 {
			end += start
		}
	}

	return end
}

// Match returns true if name matches the shell file name pattern.
// The pattern syntax is:
//
//	pattern:
//	  { term }
//	term:
//	  '*'         matches any sequence of non-path-separators
//	  '**'        matches any sequence of characters, including
//	              path separators.
//	  '?'         matches any single non-path-separator character
//	  '[' [ '^' ] { character-range } ']'
//	        character class (must be non-empty)
//	  '{' { term } [ ',' { term } ... ] '}'
//	  c           matches character c (c != '*', '?', '\\', '[')
//	  '\\' c      matches character c
//
//	character-range:
//	  c           matches character c (c != '\\', '-', ']')
//	  '\\' c      matches character c
//	  lo '-' hi   matches character c for lo <= c <= hi
//
// Match requires pattern to match all of name, not just a substring.
// The path-separator defaults to the '/' character. The only possible
// returned error is ErrBadPattern, when pattern is malformed.
//
// Note: this is meant as a drop-in replacement for path.Match() which
// always uses '/' as the path separator. If you want to support systems
// which use a different path separator (such as Windows), what you want
// is the PathMatch() function below.
func Match(pattern, name string) (bool, error) {
	return matchWithSeparator(pattern, name, '/')
}

// PathMatch is like Match except that it uses your system's path separator.
// For most systems, this will be '/'. However, for Windows, it would be '\\'.
// Note that for systems where the path separator is '\\', escaping is
// disabled.
//
// Note: this is meant as a drop-in replacement for filepath.Match().
func PathMatch(pattern, name string) (bool, error) {
	return matchWithSeparator(pattern, name, '/')
}

// Match returns true if name matches the shell file name pattern.
// The pattern syntax is:
//
//	pattern:
//	  { term }
//	term:
//	  '*'         matches any sequence of non-path-separators
//	            '**'        matches any sequence of characters, including
//	                        path separators.
//	  '?'         matches any single non-path-separator character
//	  '[' [ '^' ] { character-range } ']'
//	        character class (must be non-empty)
//	  '{' { term } [ ',' { term } ... ] '}'
//	  c           matches character c (c != '*', '?', '\\', '[')
//	  '\\' c      matches character c
//
//	character-range:
//	  c           matches character c (c != '\\', '-', ']')
//	  '\\' c      matches character c, unless separator is '\\'
//	  lo '-' hi   matches character c for lo <= c <= hi
//
// Match requires pattern to match all of name, not just a substring.
// The only possible returned error is ErrBadPattern, when pattern
// is malformed.
func matchWithSeparator(pattern, name string, separator rune) (bool, error) {
	patternComponents := splitPathOnSeparator(pattern, separator)
	nameComponents := splitPathOnSeparator(name, separator)

	return doMatching(patternComponents, nameComponents)
}

func doMatching(patternComponents, nameComponents []string) (matched bool, err error) { //nolint:cyclop
	// check for some base-cases
	patternLen, nameLen := len(patternComponents), len(nameComponents)
	if patternLen == 0 && nameLen == 0 {
		return true, nil
	}

	if patternLen == 0 || nameLen == 0 {
		return false, nil
	}

	patIdx, nameIdx := 0, 0
	for patIdx < patternLen && nameIdx < nameLen {
		// if patternComponents[patIdx] == "**" {
		if doubleStarPattern.MatchString(patternComponents[patIdx]) {
			depth := getDepth(patternComponents, patIdx, -1)

			// if our last pattern component is a doublestar, we are done -
			// doublestar will match any remaining name components, if any.
			if patIdx++; patIdx >= patternLen {
				return true, nil
			}

			// otherwise, try matching remaining components
			for ; nameIdx < nameLen; nameIdx++ {
				if nameIdx-patIdx == depth {
					break
				}

				if m, _ := doMatching(patternComponents[patIdx:], nameComponents[nameIdx:]); m {
					return true, nil
				}
			}

			return false, nil
		}

		// try matching components
		matched, err = matchComponent(patternComponents[patIdx], nameComponents[nameIdx])
		if !matched || err != nil {
			return matched, err
		}

		patIdx++
		nameIdx++
	}

	return patIdx >= patternLen && nameIdx >= nameLen, nil
}

// Glob returns the names of all files matching pattern or nil
// if there is no matching file. The syntax of pattern is the same
// as in Match. The pattern may describe hierarchical names such as
// /usr/*/bin/ed (assuming the Separator is '/').
//
// Glob ignores file system errors such as I/O errors reading directories.
// The only possible returned error is ErrBadPattern, when pattern
// is malformed.
//
// Your system path separator is automatically used. This means on
// systems where the separator is '\\' (Windows), escaping will be
// disabled.
//
// Note: this is meant as a drop-in replacement for filepath.Glob().
func Glob(fsys fs.FS, pattern string) (matches []string, err error) {
	patternComponents := splitPathOnSeparator(pattern, '/')
	if len(patternComponents) == 0 {
		return nil, nil
	}

	return doGlob(fsys, ".", patternComponents, matches, -2)
}

// Perform a glob.
func doGlob(fsys fs.FS, basedir string, components, matches []string, depth int) ([]string, error) { //nolint:gocognit,funlen,cyclop
	if depth == 0 && len(components) < 2 || depth == -1 {
		return matches, nil
	}

	patLen, patIdx := skipComponents(components)
	if patIdx > 0 {
		basedir = path.Join(basedir, path.Join(components[0:patIdx]...))
	}

	// Stat will return an error if the file/directory doesn't exist
	fi, err := fs.Stat(fsys, basedir)
	if err != nil {
		return matches, nil //nolint:nilerr
	}

	// if there are no more components, we've found a match
	if patIdx >= patLen {
		matches = append(matches, basedir)

		return matches, nil
	}

	// confirm it's a directory...
	if !fi.IsDir() {
		return matches, nil
	}

	entries, err := fs.ReadDir(fsys, basedir)
	if err != nil {
		return matches, err
	}

	lastComponent := (patIdx + 1) >= patLen

	if doubleStarPattern.MatchString(components[patIdx]) { //nolint:nestif
		depth = getDepth(components, patIdx, depth)

		// if the current component is a doublestar, we'll try depth-first
		for _, entry := range entries {
			fi, err = fs.Stat(fsys, path.Join(basedir, entry.Name()))
			if err != nil {
				continue
			}

			if fi.IsDir() {
				// recurse into directories
				if lastComponent {
					matches = append(matches, path.Join(basedir, entry.Name()))
				}

				matches, err = doGlob(fsys, path.Join(basedir, entry.Name()), components[patIdx:], matches, depth-1)
			} else if lastComponent {
				// if the pattern's last component is a doublestar, we match filenames, too
				matches = append(matches, path.Join(basedir, entry.Name()))
			}
		}

		if lastComponent {
			return matches, err // we're done
		}

		patIdx++
		lastComponent = (patIdx + 1) >= patLen
	}

	// check items in current directory and recurse
	var match bool
	for _, entry := range entries {
		match, err = matchComponent(components[patIdx], entry.Name())
		if err != nil {
			return matches, err
		}

		if match {
			if lastComponent {
				matches = append(matches, path.Join(basedir, entry.Name()))
			} else {
				matches, err = doGlob(fsys, path.Join(basedir, entry.Name()), components[patIdx+1:], matches, depth-1)
			}
		}
	}

	return matches, err
}

func skipComponents(components []string) (patLen, patIdx int) {
	// figure out how many components we don't need to glob because they're
	// just names without patterns - we'll use os.Stat below to check if that
	// path actually exists
	patLen = len(components)
	for ; patIdx < patLen; patIdx++ {
		if strings.ContainsAny(components[patIdx], "*?[{\\") {
			break
		}
	}

	return patLen, patIdx
}

func getDepth(components []string, patIdx int, depth int) int {
	depthString := strings.TrimLeft(components[patIdx], "/*")

	if depth < 0 {
		depth = 3
		if depthString != "" {
			depth, _ = strconv.Atoi(depthString)
		}
	}

	return depth
}

// Attempt to match a single pattern component with a path component.
func matchComponent(pattern, name string) (bool, error) { //nolint:funlen,cyclop
	// check some base cases
	patternLen, nameLen := len(pattern), len(name)
	if patternLen == 0 && nameLen == 0 {
		return true, nil
	}

	if patternLen == 0 {
		return false, nil
	}

	if nameLen == 0 && pattern != "*" {
		return false, nil
	}

	// check for matches one rune at a time
	patIdx, nameIdx := 0, 0
	for patIdx < patternLen && nameIdx < nameLen {
		patRune, patAdj := utf8.DecodeRuneInString(pattern[patIdx:])
		nameRune, nameAdj := utf8.DecodeRuneInString(name[nameIdx:])

		switch patRune {
		case '\\':
			// handle escaped runes
			patIdx += patAdj
			patRune, patAdj = utf8.DecodeRuneInString(pattern[patIdx:])

			switch patRune {
			case nameRune:
				patIdx += patAdj
				nameIdx += nameAdj
			case utf8.RuneError:
				return false, ErrBadPattern
			default:
				return false, nil
			}
		case '*':
			return handleStars(patIdx, patAdj, patternLen, nameIdx, nameLen, nameAdj, pattern, name)
		case '[':
			// handle character sets
			patIdx += patAdj

			endClass, err, done := handleCharacterSet(pattern, patIdx, nameRune)
			if done {
				return false, err
			}

			patIdx = endClass + 1
			nameIdx += nameAdj
		case '{':
			return handleAlternatives(patIdx, patAdj, pattern, name, nameIdx)
		case '?', nameRune:
			// handle single-rune wildcard
			patIdx += patAdj
			nameIdx += nameAdj
		default:
			return false, nil
		}
	}

	if patIdx >= patternLen && nameIdx >= nameLen {
		return true, nil
	}

	if nameIdx >= nameLen && pattern[patIdx:] == "*" || pattern[patIdx:] == "**" {
		return true, nil
	}

	return false, nil
}

func handleStars(patIdx int, patAdj int, patternLen int, nameIdx int, nameLen int, nameAdj int, pattern string, name string) (bool, error) {
	// handle stars
	if patIdx += patAdj; patIdx >= patternLen {
		// a star at the end of a pattern will always
		// match the rest of the path
		return true, nil
	}

	// check if we can make any matches
	for ; nameIdx < nameLen; nameIdx += nameAdj {
		if m, _ := matchComponent(pattern[patIdx:], name[nameIdx:]); m {
			return true, nil
		}
	}

	return false, nil
}

func handleCharacterSet(pattern string, patIdx int, nameRune rune) (int, error, bool) { //nolint:golint,gocognit,funlen,revive,cyclop
	endClass := indexRuneWithEscaping(pattern[patIdx:], ']')
	if endClass == -1 {
		return 0, ErrBadPattern, true
	}

	endClass += patIdx
	classRunes := []rune(pattern[patIdx:endClass])

	classRunesLen := len(classRunes)
	if classRunesLen > 0 { //nolint:nestif
		classIdx := 0
		matchClass := false

		if classRunes[0] == '^' {
			classIdx++
		}

		for classIdx < classRunesLen {
			low := classRunes[classIdx]
			if low == '-' {
				return 0, ErrBadPattern, true
			}

			classIdx++
			if low == '\\' {
				if classIdx < classRunesLen {
					low = classRunes[classIdx]
					classIdx++
				} else {
					return 0, ErrBadPattern, true
				}
			}

			high := low

			if classIdx < classRunesLen && classRunes[classIdx] == '-' {
				// we have a range of runes
				if classIdx++; classIdx >= classRunesLen {
					return 0, ErrBadPattern, true
				}

				high = classRunes[classIdx]
				if high == '-' {
					return 0, ErrBadPattern, true
				}

				classIdx++
				if high == '\\' {
					if classIdx < classRunesLen {
						high = classRunes[classIdx]
						classIdx++
					} else {
						return 0, ErrBadPattern, true
					}
				}
			}

			if low <= nameRune && nameRune <= high {
				matchClass = true
			}
		}

		if matchClass == (classRunes[0] == '^') {
			return 0, nil, true
		}
	} else {
		return 0, ErrBadPattern, true
	}

	return endClass, nil, false
}

func handleAlternatives(patIdx int, patAdj int, pattern string, name string, nameIdx int) (bool, error) {
	// handle alternatives such as {alt1,alt2,...}
	patIdx += patAdj

	endOptions := indexRuneWithEscaping(pattern[patIdx:], '}')
	if endOptions == -1 {
		return false, ErrBadPattern
	}

	endOptions += patIdx
	options := splitPathOnSeparator(pattern[patIdx:endOptions], ',')
	patIdx = endOptions + 1

	for _, o := range options {
		m, e := matchComponent(o+pattern[patIdx:], name[nameIdx:])
		if e != nil {
			return false, e
		}

		if m {
			return true, nil
		}
	}

	return false, nil
}
