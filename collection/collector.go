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
	"github.com/cheggaaa/pb/v3"
	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore/goforensicstore"
	"github.com/forensicanalysis/fslib"
	"github.com/pkg/errors"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type collector struct {
	SourceFS fslib.FS
	Store    *goforensicstore.ForensicStore
	tempDir  string
}

// Collect gathers data specified in artifactDefinitions from infs and runtime
// sources and saves the to the directory out in outfs
func Collect(tempDir string, source fslib.FS, store *goforensicstore.ForensicStore, sourceChannel <-chan goartifacts.NamedSource, sourceCount int) {
	c := collector{SourceFS: source, Store: store, tempDir: tempDir}

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

func (c *collector) collectSource(name string, source goartifacts.Source) {
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
		err = errors.Wrap(c.collectCommand(name, source), "could not collect command")
	case "DIRECTORY":
		err = errors.Wrap(c.collectDirectory(name, source), "could not collect directory")
	case "FILE":
		err = errors.Wrap(c.collectFile(name, source), "could not collect file")
	case "PATH":
		err = errors.Wrap(c.collectPath(name, source), "could not collect path")
	case "REGISTRY_KEY":
		err = errors.Wrap(c.collectRegistryKey(name, source), "could not collect registry key")
	case "REGISTRY_VALUE":
		err = errors.Wrap(c.collectRegistryValue(name, source), "could not collect registry value")
	case "WMI":
		err = errors.Wrap(c.collectWMI(name, source), "could not collect wmi")
	default:
		log.Printf("Unknown artifact source %s %+v", source.Type, source)
	}
	if err != nil {
		log.Print(err)
	}
}

func (c *collector) collectCommand(name string, source goartifacts.Source) error {
	if source.Attributes.Cmd == "" {
		log.Printf("No collection for %s", name)
		return nil
	}
	log.Printf("Collect Command %s %s", source.Attributes.Cmd, source.Attributes.Args)
	_, err := c.Store.InsertStruct(c.createProcess(name, source.Attributes.Cmd, source.Attributes.Args))
	if err != nil {
		return errors.Wrap(err, "could not insert struct")
	}
	return nil
}

func (c *collector) collectFile(name string, source goartifacts.Source) error {
	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToTitle(source.Type), path)
		file := c.createFile(name, true, path, name)
		if file != nil {
			_, err := c.Store.InsertStruct(file)
			if err != nil {
				return errors.Wrap(err, "could not insert struct")
			}
		}
	}
	return nil
}

func (c *collector) collectDirectory(name string, source goartifacts.Source) error {
	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, path := range source.Attributes.Paths {
		log.Printf("Collect %s %s", strings.ToLower(source.Type), path)
		file := c.createFile(name, false, path, name)
		if file != nil {
			_, err := c.Store.InsertStruct(file)
			if err != nil {
				return errors.Wrap(err, "could not insert struct")
			}
		}
	}
	return nil
}

func (c *collector) collectPath(name string, source goartifacts.Source) error {
	if len(source.Attributes.Paths) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, path := range source.Attributes.Paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			if err == nil {
				log.Printf("Collect Path %s", path)
				_, err := c.Store.InsertStruct(goforensicstore.Directory{Artifact: name, Type: "directory", Path: path})
				if err != nil {
					return errors.Wrap(err, "could not insert struct")
				}
			}
		}
	}
	return nil
}

func (c *collector) collectRegistryValue(name string, source goartifacts.Source) error {
	if len(source.Attributes.KeyValuePairs) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, kvpair := range source.Attributes.KeyValuePairs {
		log.Printf("Collect Registry Value %s %s", kvpair.Key, kvpair.Value)
		_, err := c.Store.InsertStruct(c.createRegistryValue(name, kvpair.Key, kvpair.Value))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) collectRegistryKey(name string, source goartifacts.Source) error {
	if len(source.Attributes.Keys) == 0 {
		log.Printf("No collection for %s", name)
	}
	for _, key := range source.Attributes.Keys {
		log.Printf("Collect Registry Key %s", key)
		_, err := c.Store.InsertStruct(c.createRegistryKey(name, key))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) collectWMI(name string, source goartifacts.Source) error {
	if source.Attributes.Query == "" {
		log.Printf("No collection for %s", name)
		return nil
	}
	log.Printf("Collect WMI %s", source.Attributes.Query)
	_, err := c.Store.InsertStruct(c.createWMI(name, source.Attributes.Query))
	if err != nil {
		return err
	}
	return nil
}
