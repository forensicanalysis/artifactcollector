package collection

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/forensicanalysis/artifactlib/goartifacts"
)

type collectorResolver struct {
	providesMap    map[string][]goartifacts.Source
	parameterCache map[string][]string // parameterCache lists all existing variables which can exist in some attributes
	collector      Collector
}

func NewResolver(definitions []goartifacts.ArtifactDefinition, collector Collector) *collectorResolver {
	providesMap := map[string][]goartifacts.Source{}

	for _, definition := range definitions {
		for _, source := range definition.Sources {
			for _, provide := range source.Provides {
				if _, ok := providesMap[provide.Key]; !ok {
					providesMap[provide.Key] = []goartifacts.Source{}
				}
				providesMap[provide.Key] = append(providesMap[provide.Key], source)
			}
		}
	}

	return &collectorResolver{
		providesMap:    providesMap,
		collector:      collector,
		parameterCache: map[string][]string{},
	}
}

func (r *collectorResolver) Resolve(parameter string) (out []string, err error) {
	parameters := []string{parameter}

	var re = regexp.MustCompile(`%?%(.*?)%?%`)
	replacement := true
	for replacement {
		replacement = false
		for _, p := range parameters {
			log.Println(p)

			matches := re.FindAllStringSubmatch(p, -1)

			if len(matches) > 0 {
				for _, match := range matches {
					if cacheResult, ok := r.parameterCache[match[1]]; ok {
						out = append(out, replaces(p, "%%"+match[1]+"%%", cacheResult)...)
					} else {
						resolves, err := resolve(match[1], r.providesMap, r.collector)
						if err != nil {
							return nil, err
						}
						out = append(out, replaces(p, "%%"+match[1]+"%%", resolves)...)
					}

				}
				replacement = true
			} else {
				out = append(out, p)
			}
		}
		parameters = out
		out = nil
	}
	return parameters, nil
}

func resolve(parameter string, providesMap map[string][]goartifacts.Source, collector Collector) (resolves []string, err error) {
	artifact := "artifact" // TODO
	if providingSources, ok := providesMap[parameter]; ok {
		for _, source := range providingSources {

			var provide *goartifacts.Provide
			for _, p := range source.Provides {
				if p.Key == parameter {
					provide = &p
				}
			}
			if provide == nil {
				return nil, fmt.Errorf("missing provide")
			}

			regex, err := regexp.Compile(provide.Regex)
			if err != nil {
				return nil, err
			}

			switch source.Type {
			case goartifacts.SourceType.Command:
				// COMMAND	The lines of the stdout of the command.
				process, err := collector.collectCommand(artifact, source)
				if err != nil {
					return nil, err
				}
				// TODO check if exists
				f, err := collector.SourceFS.Open(process.StdoutPath)
				if err != nil {
					return nil, err
				}

				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					for _, match := range regex.FindAllStringSubmatch(scanner.Text(), -1) {
						resolves = append(resolves, match[1])
					}
				}
				if err := scanner.Err(); err != nil {
					return nil, fmt.Errorf("reading standard input: %s", err)
				}

			case goartifacts.SourceType.File:
				// FILE	The lines of the file content.
				files, err := collector.collectFile(artifact, source)
				if err != nil {
					return nil, err
				}
				for _, file := range files {
					// TODO check if exists
					f, err := collector.SourceFS.Open(file.ExportPath)
					if err != nil {
						return nil, err
					}

					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						for _, match := range regex.FindAllStringSubmatch(scanner.Text(), -1) {
							resolves = append(resolves, match[1])
						}
					}
					if err := scanner.Err(); err != nil {
						return nil, fmt.Errorf("reading standard input: %s", err)
					}
				}

			case goartifacts.SourceType.Path:
				// PATH	The defined paths.
				directories, err := collector.collectPath(artifact, source)
				if err != nil {
					return nil, err
				}
				for _, directory := range directories {
					for _, match := range regex.FindAllStringSubmatch(directory.Path, -1) {
						resolves = append(resolves, match[1])
					}
				}

			case goartifacts.SourceType.RegistryKey:
				// REGISTRY_KEY	The key paths.
				keys, err := collector.collectRegistryKey(artifact, source)
				if err != nil {
					return nil, err
				}
				for _, key := range keys {
					for _, match := range regex.FindAllStringSubmatch(key.Key, -1) {
						resolves = append(resolves, match[1])
					}
				}

			case goartifacts.SourceType.RegistryValue:
				// REGISTRY_VALUE	The registry values.
				keys, err := collector.collectRegistryValue(artifact, source)
				if err != nil {
					return nil, err
				}
				for _, key := range keys {
					for _, value := range key.Values {
						for _, match := range regex.FindAllStringSubmatch(value.Data, -1) {
							resolves = append(resolves, match[1])
						}
					}
				}

			case goartifacts.SourceType.Wmi:
				// WMI	The values selected using the wmi_key.
				wmi, err := collector.collectWMI(artifact, source)
				if err != nil {
					return nil, err
				}
				for _, elem := range wmi.WMI {
					if wmiResult, ok := elem.(map[string]interface{}); ok {
						resolves = append(resolves, fmt.Sprint(wmiResult[provide.WMIKey]))
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("%s not provided", parameter)
}

func replaces(s, old string, news []string) (ss []string) {
	for _, newString := range news {
		ss = append(ss, strings.ReplaceAll(s, old, newString))
	}
	return
}
