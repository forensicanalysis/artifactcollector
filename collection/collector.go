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

// Package collection provides functions to collect forensicartifacts into a
// forensicstore.
package collection

import (
	"fmt"
	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore/goforensicstore"
	"github.com/forensicanalysis/fslib"
	"github.com/forensicanalysis/fslib/filesystem/registryfs"
	"github.com/forensicanalysis/fslib/filesystem/systemfs"
	"github.com/pkg/errors"
	"log"
	"strings"
)

type sourceProvider struct {
	artifact string
	sources  []goartifacts.Source
}

type LiveCollector struct {
	SourceFS   fslib.FS
	registryfs fslib.FS
	Store      *goforensicstore.ForensicStore
	TempDir    string

	providesMap map[string]sourceProvider
}

func NewCollector(store *goforensicstore.ForensicStore, tempDir string, definitions []goartifacts.ArtifactDefinition) (*LiveCollector, error) {
	providesMap := map[string]sourceProvider{}

	for _, definition := range definitions {
		for _, source := range definition.Sources {
			for _, provide := range source.Provides {
				if providingSources, ok := providesMap[provide.Key]; !ok {
					providesMap[provide.Key] = sourceProvider{
						definition.Name,
						[]goartifacts.Source{source},
					}
				} else {
					providingSources.sources = append(providingSources.sources, source)
				}
			}
		}
	}

	sourceFS, err := systemfs.New()
	if err != nil {
		return nil, errors.Wrap(err, "system fs creation failed")
	}

	return &LiveCollector{
		SourceFS:    sourceFS,
		registryfs:  registryfs.New(),
		Store:       store,
		TempDir:     tempDir,
		providesMap: providesMap,
	}, nil
}

func (c *LiveCollector) FS() fslib.FS {
	return c.SourceFS
}

func (c *LiveCollector) Registry() fslib.FS {
	return c.registryfs
}

func (c *LiveCollector) AddPartitions() bool {
	return true
}

/*
// Collect gathers data specified in artifactDefinitions from infs and runtime
// sources and saves the to the directory out in outfs
func (c *LiveCollector) Collect(sourceChannel <-chan goartifacts.NamedSource, sourceCount int) {
	tmpl := `Collect Artifact {{counters . }} {{bar . }}`
	bar := pb.ProgressBarTemplate(tmpl).Start(sourceCount)
	bar.SetRefreshRate(time.Second)

	var wg sync.WaitGroup
	workerCount := 1
	if runtime.NumCPU() > 1 {
		workerCount = runtime.NumCPU() - 1
	}
	wg.Add(workerCount)
	for id := 0; id < workerCount; id++ {
		go func(id int) {
			log.Printf("Worker %d start", id)
			for source := range sourceChannel {
				c.collectSource(source.Name, source.Source)
				bar.Increment()
			}
			log.Printf("Worker %d done", id)
			wg.Done()
		}(id)
	}
	wg.Wait()

	bar.Finish()
}
*/

func (c *LiveCollector) Collect(name string, source goartifacts.Source) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Collection for %s failed (%s)", name, r)
		}
	}()

	var err error
	switch source.Type {
	case "ARTIFACT_GROUP":
		log.Println("Artifact groups are not collected directly")
	case "COMMAND":
		_, err = c.CollectCommand(name, source)
	case "DIRECTORY":
		_, err = c.CollectDirectory(name, source)
	case "FILE":
		_, err = c.CollectFile(name, source)
	case "PATH":
		_, err = c.CollectPath(name, source)
	case "REGISTRY_KEY":
		_, err = c.CollectRegistryKey(name, source)
	case "REGISTRY_VALUE":
		_, err = c.CollectRegistryValue(name, source)
	case "WMI":
		_, err = c.CollectWMI(name, source)
	default:
		log.Printf("Unknown artifact source %s %+v", source.Type, source)
	}
	if err != nil {
		log.Print(errors.Wrap(err, fmt.Sprintf("could not collect %s", source.Type)))
	}
}

func (c *LiveCollector) CollectCommand(name string, source goartifacts.Source) (process *goforensicstore.Process, err error) {
	source = goartifacts.ExpandSource(source, c)

	if source.Attributes.Cmd == "" {
		log.Printf("No collection for %s", name)
		return nil, nil
	}
	log.Printf("Collect Command %s %s", source.Attributes.Cmd, source.Attributes.Args)
	process = c.createProcess(name, source.Attributes.Cmd, source.Attributes.Args)
	_, err = c.Store.InsertStruct(process)
	return process, errors.Wrap(err, "could not insert struct")
}

func (c *LiveCollector) CollectFile(name string, source goartifacts.Source) (files []*goforensicstore.File, err error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToTitle(source.Type), path)
		file := c.createFile(name, true, path, name)
		files = append(files, file)
		if file != nil {
			_, err := c.Store.InsertStruct(file)
			if err != nil {
				return files, errors.Wrap(err, "could not insert struct")
			}
		}
	}
	return files, nil
}

func (c *LiveCollector) CollectDirectory(name string, source goartifacts.Source) (files []*goforensicstore.File, err error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToLower(source.Type), path)
		file := c.createFile(name, false, path, name)
		files = append(files, file)
		if file != nil {
			_, err := c.Store.InsertStruct(file)
			if err != nil {
				return files, errors.Wrap(err, "could not insert struct")
			}
		}
	}
	return files, nil
}

func (c *LiveCollector) CollectPath(name string, source goartifacts.Source) (directories []*goforensicstore.Directory, err error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect Path %s", path)
		directory := goforensicstore.Directory{Artifact: name, Type: "directory", Path: path}
		directories = append(directories, &directory)
		_, err := c.Store.InsertStruct(directory)
		if err != nil {
			return directories, errors.Wrap(err, "could not insert struct")
		}
	}
	return directories, nil
}

func (c *LiveCollector) CollectRegistryValue(name string, source goartifacts.Source) (keys []*goforensicstore.RegistryKey, err error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.KeyValuePairs) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, kvpair := range source.Attributes.KeyValuePairs {
		log.Printf("Collect Registry Value %s %s", kvpair.Key, kvpair.Value)
		key := c.createRegistryValue(name, kvpair.Key, kvpair.Value)
		keys = append(keys, key)
		_, err := c.Store.InsertStruct(key)
		if err != nil {
			return keys, err
		}
	}
	return keys, nil
}

func (c *LiveCollector) CollectRegistryKey(name string, source goartifacts.Source) (keys []*goforensicstore.RegistryKey, err error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Keys) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, key := range source.Attributes.Keys {
		log.Printf("Collect Registry Key %s", key)
		k := c.createRegistryKey(name, key)
		keys = append(keys, k)
		_, err := c.Store.InsertStruct(k)
		if err != nil {
			return keys, err
		}
	}
	return keys, nil
}

func (c *LiveCollector) CollectWMI(name string, source goartifacts.Source) (process *goforensicstore.Process, err error) {
	source = goartifacts.ExpandSource(source, c)

	if source.Attributes.Query == "" {
		log.Printf("No collection for %s", name)
		return nil, nil
	}
	log.Printf("Collect WMI %s", source.Attributes.Query)
	process = c.createWMI(name, source.Attributes.Query)
	_, err = c.Store.InsertStruct(process)
	return process, errors.Wrap(err, "could not insert struct")
}
