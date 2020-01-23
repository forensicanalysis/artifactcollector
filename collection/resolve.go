package collection

import (
	"bufio"
	"fmt"
	"regexp"

	"github.com/forensicanalysis/artifactlib/goartifacts"
)

func (c *LiveCollector) Resolve(parameter string) (resolves []string, err error) {
	if providingSources, ok := c.providesMap[parameter]; ok {
		for _, source := range providingSources.sources {

			i := -1
			for index, p := range source.Provides {
				if p.Key == parameter {
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

			switch source.Type {
			case goartifacts.SourceType.Command:
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
				if err := scanner.Err(); err != nil {
					return nil, fmt.Errorf("reading standard input: %s", err)
				}

			case goartifacts.SourceType.File:
				// FILE	The lines of the file content.
				files, err := c.CollectFile(providingSources.artifact, source)
				if err != nil {
					return nil, err
				}
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
						return nil, fmt.Errorf("reading standard input: %s", err)
					}
				}

			case goartifacts.SourceType.Path:
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

			case goartifacts.SourceType.RegistryKey:
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

			case goartifacts.SourceType.RegistryValue:
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

			case goartifacts.SourceType.Wmi:
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
			}
		}
	}

	return resolves, nil
}
