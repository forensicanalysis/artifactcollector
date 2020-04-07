// Copyright (c) 2019-2020 Siemens AG
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

package run

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/mholt/archiver"
	"github.com/pkg/errors"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore/goforensicstore"
)

// Collection is the output of a run that can be used to further process the output
// (e.g. send the output to a SFTP server).
type Collection struct {
	Name string
	Path string
}

// Run performs the full artifact collection process.
func Run(config *collection.Configuration, artifactDefinitions []goartifacts.ArtifactDefinition, embedded map[string][]byte) (c *Collection) {
	//nolint:gocyclo
	if len(config.Artifacts) == 0 {
		fmt.Println("No artifacts selected in config")
		return nil
	}

	// setup
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "artifactcollector"
	}
	if config.Case != "" {
		hostname = config.Case + "-" + hostname
	}
	collectionName := fmt.Sprintf("%s_%s", hostname, time.Now().UTC().Format("2006-01-02T15-04-05"))

	// setup logging
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)
	logfile, logfileError := os.OpenFile(collectionName+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if logfileError != nil {
		log.Printf("Could not open logfile %s\n", logfileError)
	} else {
		log.SetOutput(logfile)
		defer logfile.Close()
	}

	defer func() {
		if r := recover(); r != nil {
			logPrint("A critical error occurred: ", r, string(debug.Stack()))
			c = nil
		}
	}()

	// start running
	logPrint("Start to collect forensic artifacts. This might take a while.")
	start := time.Now()

	// unpack internal files
	tempDir, err := unpack(embedded)
	if err != nil {
		logPrint(err)
		return nil
	}
	defer os.RemoveAll(tempDir) // clean up

	// enforce admin rights
	if err = enforceAdmin(!config.User); err != nil {
		logPrint(err)
		return nil
	}

	// create store
	storeName, store, err := createStore(collectionName, config, artifactDefinitions)
	if err != nil {
		logPrint(err)
		return nil
	}

	// add store as log writer
	if logfileError == nil {
		log.SetOutput(io.MultiWriter(logfile, &storeLogger{store}))
	} else {
		log.SetOutput(io.MultiWriter(&storeLogger{store}))
	}

	collector, err := collection.NewCollector(store, tempDir, artifactDefinitions)
	if err != nil {
		logPrint(errors.Wrap(err, "LiveCollector creation failed"))
		return nil
	}

	// select from entrypoint
	if config.Artifacts != nil {
		artifactDefinitions = goartifacts.FilterName(config.Artifacts, artifactDefinitions)
	}

	// select supported os
	artifactDefinitions = goartifacts.FilterOS(artifactDefinitions)

	// setup bar
	tmpl := `Collecting {{string . "artifact"}} ({{counters . }} {{bar . }})`
	bar := pb.ProgressBarTemplate(tmpl).Start(len(artifactDefinitions))
	bar.SetRefreshRate(time.Second)

	// collect artifacts
	for _, artifactDefinition := range artifactDefinitions {
		startArtifact := time.Now()
		bar.Set("artifact", artifactDefinition.Name)
		bar.Increment()
		for _, source := range artifactDefinition.Sources {
			collector.Collect(artifactDefinition.Name, source)
		}
		log.Printf("Collected %s in %.1f seconds\n", artifactDefinition.Name, time.Since(startArtifact).Seconds())
	}

	// finish bar
	bar.Finish()

	log.Printf("Collected artifacts in %.1f seconds\n", time.Since(start).Seconds())

	// remove store logger
	if logfileError == nil {
		log.SetOutput(logfile)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	err = store.Close()
	if err != nil {
		logPrint(errors.Wrap(err, "Close Store failed"))
		return nil
	}

	logPrint("Compress results.")
	time.Sleep(time.Millisecond * 500)

	zipPath := ""

	// compress data
	if err := archiver.Archive([]string{storeName}, storeName+".zip"); err != nil {
		log.Printf("compression failed: %s", err)
	} else {
		zipPath = storeName + ".zip"
		err = os.RemoveAll(storeName)
		if err != nil {
			log.Printf("removal failed: %s", err)
		}
	}

	logPrint("Collection done.")
	time.Sleep(time.Second)

	return &Collection{
		Name: collectionName,
		Path: zipPath,
	}
}

func unpack(embedded map[string][]byte) (tempDir string, err error) {
	tempDir, err = ioutil.TempDir("", "ac")
	if err != nil {
		return tempDir, err
	}

	for path, content := range embedded {
		if err := os.MkdirAll(filepath.Join(tempDir, filepath.Dir(path)), 0700); err != nil {
			return tempDir, err
		}
		if err := ioutil.WriteFile(filepath.Join(tempDir, path), content, 0644); err != nil {
			return tempDir, err
		}
		log.Printf("Unpacking %s", path)
	}

	return tempDir, nil
}

func enforceAdmin(forceAdmin bool) error {
	switch {
	case !forceAdmin:
		return nil
	case runtime.GOOS == "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return errors.New("Need to be windows admin")
		}
		return nil
	case os.Getgid() != 0:
		return errors.New("Need to be root")
	default:
		return nil
	}
}

func createStore(collectionName string, config *collection.Configuration, definitions []goartifacts.ArtifactDefinition) (string, *goforensicstore.ForensicStore, error) {
	storeName := fmt.Sprintf("%s.forensicstore", collectionName)
	store, err := goforensicstore.NewJSONLite(storeName)
	if err != nil {
		return "", nil, err
	}

	// insert configuration into store
	config.Type = "_config"
	_, err = store.InsertStruct(config)
	if err != nil {
		log.Println(err)
	}

	// insert artifact definitions into store
	for _, artifact := range definitions {
		_, err = store.InsertStruct(
			struct {
				Data string `yaml:"artifacts"`
				Type string `yaml:"type,omitempty"`
			}{
				fmt.Sprintf("%#v", artifact),
				"_artifact-definition",
			},
		)
		if err != nil {
			log.Println(err)
		}
	}

	return storeName, store, nil
}

func logPrint(a ...interface{}) {
	log.Println(a...)
	fmt.Println(a...)
}
