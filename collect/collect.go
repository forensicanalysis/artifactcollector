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

package collect

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/forensicanalysis/artifactcollector/artifacts"
	"github.com/forensicanalysis/artifactcollector/collector"
	"github.com/forensicanalysis/artifactcollector/store"
)

var (
	windowsZipTempDir = regexp.MustCompile(`(?i)C:\\Windows\\system32`)
	sevenZipTempDir   = regexp.MustCompile(`(?i)C:\\Users\\.*\\AppData\\Local\\Temp\\.*`)
)

func Collect(config *collector.Configuration, artifactDefinitions []artifacts.ArtifactDefinition, embedded map[string][]byte) (run *Run, err error) { //nolint:funlen
	defer func() {
		if r := recover(); r != nil {
			logPrint("A critical error occurred: ", r, string(debug.Stack()))
		}
	}()

	start := time.Now()

	run = NewRun(config)

	setupLogging(run.LogfilePath)

	defer closeLogging()

	logPrint("Start to collect forensic artifacts. This might take a while.")

	// unpack internal files
	tempDir, err := unpack(embedded)
	if err != nil {
		logPrint(err)

		return run, err
	}
	defer os.RemoveAll(tempDir) // clean up

	if err := enforceAdmin(!config.User); err != nil {
		logPrint(err)

		return run, err
	}

	filteredArtifactDefinitions, err := filterArtifacts(config, artifactDefinitions)
	if err != nil {
		logPrint(err)

		return run, err
	}

	// create store
	store, teardownStore, err := createStore(run.StorePath, config, filteredArtifactDefinitions)
	if err != nil {
		logPrint(err)

		return run, err
	}

	// also log to store
	addLogger(store)

	// collect artifacts
	if err := collectArtifacts(store, tempDir, artifactDefinitions, filteredArtifactDefinitions, start); err != nil {
		logPrint(err)

		return run, err
	}

	// remove store logger
	resetLogger()

	if err := teardownStore(); err != nil {
		logPrint(fmt.Errorf("Close Store failed: %s", err))

		return run, fmt.Errorf("Close Store failed: %s", err)
	}

	logPrint("Collection done.")

	return run, nil
}

func filterArtifacts(config *collector.Configuration, definitions []artifacts.ArtifactDefinition) ([]artifacts.ArtifactDefinition, error) {
	filtered := definitions

	if config.Artifacts != nil {
		filtered = artifacts.FilterName(config.Artifacts, definitions)
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("No artifacts selected in config")
	}

	return filtered, nil
}

func collectArtifacts(store *store.ZipStore, tempDir string, artifactDefinitions []artifacts.ArtifactDefinition, filteredArtifactDefinitions []artifacts.ArtifactDefinition, start time.Time) error {
	collector, err := collector.NewCollector(store, tempDir, artifactDefinitions)
	if err != nil {
		return fmt.Errorf("Collector creation failed: %w", err)
	}

	total := len(filteredArtifactDefinitions)

	// collect artifacts
	for i := 0; i < total; i++ {
		collectArtifact(collector, filteredArtifactDefinitions[i], i, total)
	}

	log.Printf("Collected artifacts in %.1f seconds\n", time.Since(start).Seconds())

	return nil
}

func collectArtifact(collector *collector.Collector, artifactDefinition artifacts.ArtifactDefinition, i, total int) {
	defer func() {
		if r := recover(); r != nil {
			logPrint("A critical error occurred: ", r, string(debug.Stack()))
		}
	}()

	startArtifact := time.Now()

	logPrint(fmt.Sprintf("Collecting %s (%d/%d)", artifactDefinition.Name, i+1, total))

	for _, source := range artifactDefinition.Sources {
		collector.Collect(artifactDefinition.Name, source)
	}

	log.Printf("Collected %s in %.1f seconds\n", artifactDefinition.Name, time.Since(startArtifact).Seconds())
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
			logPrint("Need to be windows admin")

			return os.ErrPermission
		}

		return nil
	case os.Getgid() != 0:
		logPrint("need to be root")

		return os.ErrPermission
	default:
		return nil
	}
}
