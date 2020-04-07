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

package collection

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/forensicanalysis/artifactlib/goartifacts"
)

// Resolve returns a list of values that can be used for the placeholder parameter.
func (c *LiveCollector) Resolve(parameter string) ([]string, error) {
	parameter = strings.TrimPrefix(parameter, "environ_")

	providingSources, ok := c.providesMap[parameter]
	if !ok {
		return nil, fmt.Errorf("parameter %s not provided", parameter)
	}

	if cachedResolves, ok := c.knowledgeBase[parameter]; ok {
		return cachedResolves, nil
	}

	var resolves []string
	for _, source := range providingSources.sources {
		i := -1
		for index, p := range source.Provides {
			if strings.TrimPrefix(p.Key, "environ_") == parameter {
				i = index
			}
		}
		if i == -1 {
			return nil, fmt.Errorf("missing provide")
		}

		provide := source.Provides[i]

		regex, err := regexp.Compile(provide.Regex)
		if err != nil {
			return nil, err
		}

		var resolve []string
		switch source.Type {
		case goartifacts.SourceType.Command:
			resolve, err = c.resolveCommand(providingSources, source, provide, regex)
		case goartifacts.SourceType.File:
			resolve, err = c.resolveFile(providingSources, source, provide, regex)
		case goartifacts.SourceType.Path:
			resolve, err = c.resolvePath(providingSources, source, provide, regex)
		case goartifacts.SourceType.RegistryKey:
			resolve, err = c.resolveRegistryKey(providingSources, source, provide, regex)
		case goartifacts.SourceType.RegistryValue:
			resolve, err = c.resolveRegistryValue(providingSources, source, provide, regex)
		case goartifacts.SourceType.Wmi:
			resolve, err = c.resolveWMI(providingSources, source, provide, regex)
		}
		if err != nil {
			return nil, err
		}
		resolves = append(resolves, resolve...)
	}

	// cache results
	c.knowledgeBase[parameter] = resolves
	log.Println(parameter, resolves)

	return resolves, nil
}

func (c *LiveCollector) resolveCommand(providingSources sourceProvider, source goartifacts.Source, provide goartifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// COMMAND	The lines of the stdout of the command.
	process, err := c.CollectCommand(providingSources.artifact, source)
	if err != nil {
		return nil, err
	}
	// TODO check if exists
	f, err := c.SourceFS.Open(process.StdoutPath)
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

func (c *LiveCollector) resolveFile(providingSources sourceProvider, source goartifacts.Source, provide goartifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	// FILE	The lines of the file content.
	files, err := c.CollectFile(providingSources.artifact, source)
	if err != nil {
		return nil, err
	}
	var resolves []string

	for _, file := range files {
		// TODO check if exists
		f, err := c.SourceFS.Open(file.ExportPath)
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

func (c *LiveCollector) resolvePath(providingSources sourceProvider, source goartifacts.Source, provide goartifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// PATH	The defined paths.
	directories, err := c.CollectPath(providingSources.artifact, source)
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

func (c *LiveCollector) resolveRegistryKey(providingSources sourceProvider, source goartifacts.Source, provide goartifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// REGISTRY_KEY	The key paths.
	keys, err := c.CollectRegistryKey(providingSources.artifact, source)
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

func (c *LiveCollector) resolveRegistryValue(providingSources sourceProvider, source goartifacts.Source, provide goartifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// REGISTRY_VALUE	The registry values.
	keys, err := c.CollectRegistryValue(providingSources.artifact, source)
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

func (c *LiveCollector) resolveWMI(providingSources sourceProvider, source goartifacts.Source, provide goartifacts.Provide, regex *regexp.Regexp) ([]string, error) {
	var resolves []string
	// WMI	The values selected using the wmi_key.
	wmi, err := c.CollectWMI(providingSources.artifact, source)
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
