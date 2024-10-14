// Copyright (c) 2020 Siemens AG
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

package collector

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/forensicanalysis/artifactcollector/artifacts"
)

// Resolve returns a list of values that can be used for the placeholder parameter.
func (c *Collector) Resolve(parameter string) ([]string, error) { //nolint:cyclop,funlen
	parameter = strings.ToLower(parameter)
	parameter = strings.TrimPrefix(parameter, "environ_")

	providingSources, ok := c.providesMap[parameter]
	if !ok {
		return nil, fmt.Errorf("parameter %s not provided", parameter)
	}

	if cachedResolves, ok := c.knowledgeBase[parameter]; ok {
		return cachedResolves, nil
	}

	var resolves []string

	resolvesSet := map[string]bool{}

	for _, source := range providingSources {
		provide, err := getProvide(source, parameter)
		if err != nil {
			return nil, err
		}

		regex, err := regexp.Compile(provide.Regex)
		if err != nil {
			return nil, err
		}

		var resolve []string

		switch source.Type {
		case artifacts.SourceType.Command:
			resolve, err = c.resolveCommand(source, provide, regex)
		case artifacts.SourceType.File:
			resolve, err = c.resolveFile(source, provide, regex)
		case artifacts.SourceType.Path:
			resolve, err = c.resolvePath(source, provide, regex)
		case artifacts.SourceType.RegistryKey:
			resolve, err = c.resolveRegistryKey(source, provide, regex)
		case artifacts.SourceType.RegistryValue:
			resolve, err = c.resolveRegistryValue(source, provide, regex)
		case artifacts.SourceType.Wmi:
			resolve, err = c.resolveWMI(source, provide, regex)
		}

		if err != nil {
			return nil, err
		}

		for _, r := range resolve {
			if _, ok := resolvesSet[r]; !ok {
				resolvesSet[r] = true

				resolves = append(resolves, r)
			}
		}
	}

	// cache results
	c.knowledgeBase[parameter] = resolves
	log.Printf("%s resolves to %v\n", parameter, resolves)

	return resolves, nil
}

func getProvide(source artifacts.Source, parameter string) (artifacts.Provide, error) {
	i := -1

	for index, p := range source.Provides {
		if strings.TrimPrefix(p.Key, "environ_") == parameter {
			i = index
		}
	}

	if i == -1 {
		return artifacts.Provide{}, fmt.Errorf("missing provide")
	}

	provide := source.Provides[i]

	return provide, nil
}

func (c *Collector) resolveCommand(source artifacts.Source, provide artifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// COMMAND The lines of the stdout of the command.
	process, err := c.collectCommand(source.Parent, source)
	if err != nil {
		return nil, err
	}
	// TODO check if exists
	f, err := c.Store.LoadFile(process.StdoutPath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if provide.Regex != "" {
			for _, match := range regex.FindAllStringSubmatch(scanner.Text(), -1) {
				if len(match) > 1 {
					resolves = append(resolves, match[1])
				}
			}
		} else {
			resolves = append(resolves, scanner.Text())
		}
	}

	err = scanner.Err()

	return resolves, fmt.Errorf("reading standard input: %w", err)
}

func (c *Collector) resolveFile(source artifacts.Source, provide artifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	// FILE The lines of the file content.
	files, err := c.collectFile(source.Parent, source)
	if err != nil {
		return nil, err
	}

	var resolves []string

	for _, file := range files {
		// TODO check if exists
		f, err := c.Store.LoadFile(file.ExportPath)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if provide.Regex != "" {
				for _, match := range regex.FindAllStringSubmatch(scanner.Text(), -1) {
					if len(match) > 1 {
						resolves = append(resolves, match[1])
					}
				}
			} else {
				resolves = append(resolves, scanner.Text())
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading standard input: %w", err)
		}
	}

	return resolves, nil
}

func (c *Collector) resolvePath(source artifacts.Source, provide artifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// PATH The defined paths.
	directories, err := c.collectPath(source.Parent, source)
	if err != nil {
		return nil, err
	}

	for _, directory := range directories {
		if provide.Regex != "" {
			for _, match := range regex.FindAllStringSubmatch(directory.Path, -1) {
				if len(match) > 1 {
					resolves = append(resolves, match[1])
				}
			}
		} else {
			resolves = append(resolves, directory.Path)
		}
	}

	return resolves, nil
}

func (c *Collector) resolveRegistryKey(source artifacts.Source, provide artifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// REGISTRY_KEY The key paths.
	keys, err := c.collectRegistryKey(source.Parent, source)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		if provide.Regex != "" {
			for _, match := range regex.FindAllStringSubmatch(key.Key, -1) {
				if len(match) > 1 {
					resolves = append(resolves, match[1])
				}
			}
		} else {
			resolves = append(resolves, key.Key)
		}
	}

	return resolves, nil
}

func (c *Collector) resolveRegistryValue(source artifacts.Source, provide artifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// REGISTRY_VALUE The registry values.
	keys, err := c.collectRegistryValue(source.Parent, source)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		for _, value := range key.Values {
			if provide.Regex != "" {
				for _, match := range regex.FindAllStringSubmatch(value.Data, -1) {
					if len(match) > 1 {
						resolves = append(resolves, match[1])
					}
				}
			} else {
				resolves = append(resolves, value.Data)
			}
		}
	}

	return resolves, nil
}

func (c *Collector) resolveWMI(source artifacts.Source, provide artifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// WMI The values selected using the wmi_key.
	wmi, err := c.collectWMI(source.Parent, source)
	if err != nil {
		return nil, err
	}

	for _, elem := range wmi.WMI {
		if wmiResult, ok := elem.(map[string]interface{}); ok {
			if provide.Regex != "" {
				for _, match := range regex.FindAllStringSubmatch(fmt.Sprint(wmiResult[provide.WMIKey]), -1) {
					if len(match) > 1 {
						resolves = append(resolves, match[1])
					}
				}
			} else {
				resolves = append(resolves, fmt.Sprint(wmiResult[provide.WMIKey]))
			}
		}
	}

	return resolves, nil
}
