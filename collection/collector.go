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
	"io"
	"log"
	"runtime"
	"strings"

	"github.com/spf13/afero"

	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/fslib"
	"github.com/forensicanalysis/fslib/filesystem/registryfs"
	"github.com/forensicanalysis/fslib/filesystem/systemfs"
)

// The LiveCollector can resolve and collect artifact on live systems.
type LiveCollector struct {
	SourceFS   fslib.FS
	registryfs fslib.FS
	Store      Store
	TempDir    string

	providesMap   map[string][]goartifacts.Source
	knowledgeBase map[string][]string
	prefixes      []string
}

type Store interface {
	SetFS(fs afero.Fs)
	InsertStruct(element interface{}) (string, error)
	StoreFile(filePath string) (storePath string, file io.WriteCloser, teardown func() error, err error)
	LoadFile(filePath string) (file io.ReadCloser, teardown func() error, err error)
}

// NewCollector creates a new LiveCollector that collects the given
// ArtifactDefinitions.
func NewCollector(store Store, tempDir string, definitions []goartifacts.ArtifactDefinition) (*LiveCollector, error) {
	providesMap := map[string][]goartifacts.Source{}

	definitions = goartifacts.FilterOS(definitions)

	for _, definition := range definitions {
		for _, source := range definition.Sources {
			for _, provide := range source.Provides {
				key := strings.TrimPrefix(provide.Key, "environ_")
				if providingSources, ok := providesMap[key]; !ok {
					providesMap[key] = []goartifacts.Source{source}
				} else {
					providesMap[key] = append(providingSources, source)
				}
			}
		}
	}

	sourceFS, err := systemfs.New()
	if err != nil {
		return nil, fmt.Errorf("system fs creation failed: %w", err)
	}

	lc := &LiveCollector{
		SourceFS:      sourceFS,
		registryfs:    registryfs.New(),
		Store:         store,
		TempDir:       tempDir,
		providesMap:   providesMap,
		knowledgeBase: map[string][]string{},
	}

	if runtime.GOOS == "windows" {
		root, err := sourceFS.Open("/")
		if err != nil {
			return nil, err
		}
		names, err := root.Readdirnames(0)
		if err != nil {
			return nil, err
		}
		lc.prefixes = names
	}

	return lc, nil
}

// FS returns the used FileSystem.
func (c *LiveCollector) FS() fslib.FS {
	return c.SourceFS
}

// Registry returns the used Registry.
func (c *LiveCollector) Registry() fslib.FS {
	return c.registryfs
}

// AddPartitions returns if partitions should be added to Windows paths.
func (c *LiveCollector) Prefixes() []string {
	return c.prefixes
}

// Collect dispatches specific collection functions for different sources.
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
		_, err = c.collectCommand(name, source)
	case "DIRECTORY":
		_, err = c.collectDirectory(name, source)
	case "FILE":
		_, err = c.collectFile(name, source)
	case "PATH":
		_, err = c.collectPath(name, source)
	case "REGISTRY_KEY":
		_, err = c.collectRegistryKey(name, source)
	case "REGISTRY_VALUE":
		_, err = c.collectRegistryValue(name, source)
	case "WMI":
		_, err = c.collectWMI(name, source)
	default:
		log.Printf("Unknown artifact source %s %+v", source.Type, source)
	}
	if err != nil {
		log.Print(fmt.Errorf("could not collect %s: %w", source.Type, err))
	}
}

// collectCommand collects a COMMAND source to the forensicstore.
func (c *LiveCollector) collectCommand(name string, source goartifacts.Source) (*Process, error) {
	source = goartifacts.ExpandSource(source, c)

	if source.Attributes.Cmd == "" {
		log.Printf("No collection for %s", name)
		return nil, nil
	}
	log.Printf("Collect Command %s %s", source.Attributes.Cmd, source.Attributes.Args)
	process := c.createProcess(name, source.Attributes.Cmd, source.Attributes.Args)
	_, err := c.Store.InsertStruct(process)
	if err != nil {
		return nil, fmt.Errorf("could not insert struct: %w", err)
	}
	return process, nil
}

// collectFile collects a FILE source to the forensicstore.
func (c *LiveCollector) collectFile(name string, osource goartifacts.Source) ([]*File, error) {
	source := goartifacts.ExpandSource(osource, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	var files []*File
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToTitle(source.Type), path)
		file := c.createFile(name, true, path, name)
		files = append(files, file)
		if file != nil {
			_, err := c.Store.InsertStruct(file)
			if err != nil {
				return files, fmt.Errorf("could not insert struct: %w", err)
			}
		}
	}
	return files, nil
}

// collectDirectory collects a DIRECTORY source to the forensicstore.
func (c *LiveCollector) collectDirectory(name string, source goartifacts.Source) ([]*File, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	var files []*File
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToLower(source.Type), path)
		file := c.createFile(name, false, path, name)
		files = append(files, file)
		if file != nil {
			_, err := c.Store.InsertStruct(file)
			if err != nil {
				return files, fmt.Errorf("could not insert struct: %w", err)
			}
		}
	}
	return files, nil
}

// collectPath collects a PATH source to the forensicstore.
func (c *LiveCollector) collectPath(name string, source goartifacts.Source) ([]*Directory, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	var directories []*Directory
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect Path %s", path)
		directory := NewDirectory()
		directory.Artifact = name
		directory.Path = path
		directories = append(directories, directory)
		_, err := c.Store.InsertStruct(directory)
		if err != nil {
			return directories, fmt.Errorf("could not insert struct: %w", err)
		}
	}
	return directories, nil
}

// collectRegistryKey collects a REGISTRY_KEY source to the forensicstore.
func (c *LiveCollector) collectRegistryKey(name string, source goartifacts.Source) ([]*RegistryKey, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Keys) == 0 {
		log.Printf("No collection for %s", name)
	}
	var keys []*RegistryKey
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

// collectRegistryValue collects a REGISTRY_VALUE source to the forensicstore.
func (c *LiveCollector) collectRegistryValue(name string, source goartifacts.Source) ([]*RegistryKey, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.KeyValuePairs) == 0 {
		log.Printf("No collection for %s", name)
	}
	var keys []*RegistryKey
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

// collectWMI collects a WMI source to the forensicstore.
func (c *LiveCollector) collectWMI(name string, source goartifacts.Source) (*Process, error) {
	source = goartifacts.ExpandSource(source, c)

	if source.Attributes.Query == "" {
		log.Printf("No collection for %s", name)
		return nil, nil
	}
	log.Printf("Collect WMI %s", source.Attributes.Query)
	process := c.createWMI(name, source.Attributes.Query)
	_, err := c.Store.InsertStruct(process)
	if err != nil {
		return nil, fmt.Errorf("could not insert struct: %w", err)
	}
	return process, nil
}
