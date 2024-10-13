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

// Package collector provides functions to collect forensicartifacts into a
// forensicstore.
package collector

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"runtime"
	"strings"

	"github.com/forensicanalysis/fslib/registryfs"
	"github.com/forensicanalysis/fslib/systemfs"

	"github.com/forensicanalysis/artifactcollector/goartifacts"
)

// The Collector can resolve and collect artifact on live systems.
type Collector struct {
	SourceFS   fs.FS
	registryfs fs.FS
	Store      Store
	TempDir    string

	providesMap   map[string][]goartifacts.Source
	knowledgeBase map[string][]string
	prefixes      []string
}

type Store interface {
	InsertStruct(id string, element interface{}) error
	StoreFile(filePath string) (storePath string, file io.Writer, err error)
	LoadFile(filePath string) (file io.Reader, err error)
}

// NewCollector creates a new Collector that collects the given
// ArtifactDefinitions.
func NewCollector(store Store, tempDir string, definitions []goartifacts.ArtifactDefinition) (*Collector, error) {
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

	lc := &Collector{
		SourceFS:      sourceFS,
		registryfs:    registryfs.New(),
		Store:         store,
		TempDir:       tempDir,
		providesMap:   providesMap,
		knowledgeBase: map[string][]string{},
	}

	if runtime.GOOS == "windows" {
		var names []string

		entries, err := fs.ReadDir(sourceFS, ".")
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			names = append(names, entry.Name())
		}

		lc.prefixes = names
	}

	return lc, nil
}

// FS returns the used FileSystem.
func (c *Collector) FS() fs.FS {
	return c.SourceFS
}

// Registry returns the used Registry.
func (c *Collector) Registry() fs.FS {
	return c.registryfs
}

// AddPartitions returns if partitions should be added to Windows paths.
func (c *Collector) Prefixes() []string {
	return c.prefixes
}

// Collect dispatches specific collection functions for different sources.
func (c *Collector) Collect(name string, source goartifacts.Source) { //nolint:cyclop
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
func (c *Collector) collectCommand(name string, source goartifacts.Source) (*Process, error) {
	source = goartifacts.ExpandSource(source, c)

	if source.Attributes.Cmd == "" {
		log.Printf("No collection for %s", name)

		return nil, nil
	}

	log.Printf("Collect Command %s %s", source.Attributes.Cmd, source.Attributes.Args)
	process := c.createProcess(name, source.Attributes.Cmd, source.Attributes.Args)

	err := c.Store.InsertStruct(process.ID, process)
	if err != nil {
		return nil, fmt.Errorf("could not insert struct: %w", err)
	}

	return process, nil
}

func fsPath(s string) string {
	s = strings.TrimLeft(s, "/")
	if s == "" {
		return "."
	}

	return s
}

// collectFile collects a FILE source to the forensicstore.
func (c *Collector) collectFile(name string, osource goartifacts.Source) ([]*File, error) {
	source := goartifacts.ExpandSource(osource, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}

	var files []*File

	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToTitle(source.Type), path)
		file := c.createFile(name, true, fsPath(path), name)
		files = append(files, file)

		if file != nil {
			err := c.Store.InsertStruct(file.ID, file)
			if err != nil {
				return files, fmt.Errorf("could not insert struct: %w", err)
			}
		}
	}

	return files, nil
}

// collectDirectory collects a DIRECTORY source to the forensicstore.
func (c *Collector) collectDirectory(name string, source goartifacts.Source) ([]*File, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}

	var files []*File

	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToLower(source.Type), path)
		file := c.createFile(name, false, fsPath(path), name)
		files = append(files, file)

		if file != nil {
			err := c.Store.InsertStruct(file.ID, file)
			if err != nil {
				return files, fmt.Errorf("could not insert struct: %w", err)
			}
		}
	}

	return files, nil
}

// collectPath collects a PATH source to the forensicstore.
func (c *Collector) collectPath(name string, source goartifacts.Source) ([]*Directory, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}

	var directories []*Directory

	for _, path := range source.Attributes.Paths {
		log.Printf("Collect Path %s", path)

		directory := NewDirectory()
		directory.Artifact = name
		directory.Path = fsPath(path)
		directories = append(directories, directory)

		err := c.Store.InsertStruct(directory.ID, directory)
		if err != nil {
			return directories, fmt.Errorf("could not insert struct: %w", err)
		}
	}

	return directories, nil
}

// collectRegistryKey collects a REGISTRY_KEY source to the forensicstore.
func (c *Collector) collectRegistryKey(name string, source goartifacts.Source) ([]*RegistryKey, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.Keys) == 0 {
		log.Printf("No collection for %s", name)
	}

	var keys []*RegistryKey

	for _, key := range source.Attributes.Keys {
		log.Printf("Collect Registry Key %s", key)
		k := c.createRegistryKey(name, fsPath(key))
		keys = append(keys, k)

		err := c.Store.InsertStruct(k.ID, k)
		if err != nil {
			return keys, err
		}
	}

	return keys, nil
}

// collectRegistryValue collects a REGISTRY_VALUE source to the forensicstore.
func (c *Collector) collectRegistryValue(name string, source goartifacts.Source) ([]*RegistryKey, error) {
	source = goartifacts.ExpandSource(source, c)

	if len(source.Attributes.KeyValuePairs) == 0 {
		log.Printf("No collection for %s", name)
	}

	var keys []*RegistryKey

	for _, kvpair := range source.Attributes.KeyValuePairs {
		log.Printf("Collect Registry Value %s %s", kvpair.Key, kvpair.Value)
		key := c.createRegistryValue(name, fsPath(kvpair.Key), kvpair.Value)
		keys = append(keys, key)

		err := c.Store.InsertStruct(key.ID, key)
		if err != nil {
			return keys, err
		}
	}

	return keys, nil
}

// collectWMI collects a WMI source to the forensicstore.
func (c *Collector) collectWMI(name string, source goartifacts.Source) (*Process, error) {
	source = goartifacts.ExpandSource(source, c)

	if source.Attributes.Query == "" {
		log.Printf("No collection for %s", name)

		return nil, nil
	}

	log.Printf("Collect WMI %s", source.Attributes.Query)
	process := c.createWMI(name, source.Attributes.Query)

	err := c.Store.InsertStruct(process.ID, process)
	if err != nil {
		return nil, fmt.Errorf("could not insert struct: %w", err)
	}

	return process, nil
}
