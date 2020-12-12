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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"time"

	"crawshaw.io/sqlite"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactlib/goartifacts"
)

// Collection is the output of a run that can be used to further process the output
// (e.g. send the output to a SFTP server).
type Collection struct {
	Name string
	Path string
}

// Run performs the full artifact collection process.
func Run(config *collection.Configuration, artifactDefinitions []goartifacts.ArtifactDefinition, embedded map[string][]byte) (c *Collection) { //nolint:gocyclo,funlen
	if len(config.Artifacts) == 0 {
		fmt.Println("No artifacts selected in config")
		return nil
	}

	var outputDirFlag string
	flag.StringVar(&outputDirFlag, "o", "", "Output directory for forensicstore and log file")
	flag.Parse()

	cwd, _ := os.Getwd()
	windowsZipTempDir := regexp.MustCompile(`(?i)C:\\Windows\\system32`)
	sevenZipTempDir := regexp.MustCompile(`(?i)C:\\Users\\.*\\AppData\\Local\\Temp\\.*`)

	// output dir order:
	// 1. -o flag given
	// 2. implemented in config
	// 3.1. running from zip -> Desktop
	// 3.2. otherwise -> current directory
	switch {
	case outputDirFlag != "":
		config.OutputDir = outputDirFlag
	case config.OutputDir != "":
	case windowsZipTempDir.MatchString(cwd) || sevenZipTempDir.MatchString(cwd):
		fmt.Println("Running from zip, results will be available on Desktop")
		homedir, _ := os.UserHomeDir()
		config.OutputDir = filepath.Join(homedir, "Desktop")
	default:
		config.OutputDir = "" // current directory
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
	logfilePath := filepath.Join(config.OutputDir, collectionName+".log")
	logfile, logfileError := os.OpenFile(logfilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
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
		return nil
	}

	// select from entrypoint
	filteredArtifactDefinitions := artifactDefinitions
	if config.Artifacts != nil {
		filteredArtifactDefinitions = goartifacts.FilterName(config.Artifacts, artifactDefinitions)
	}

	// create store
	collectionPath := filepath.Join(config.OutputDir, collectionName)
	storeName, store, teardown, err := createStore(collectionPath, config, filteredArtifactDefinitions)
	if err != nil {
		logPrint(err)
		return nil
	}

	if config.FS != nil {
		store.SetFS(config.FS)
	}

	// add store as log writer
	storeLogger, storeLoggerError := newStoreLogger(store)
	if storeLoggerError != nil {
		log.Printf("Could not setup logging to forensicstore: %s", storeLoggerError)
	}
	switch {
	case logfileError == nil && storeLoggerError == nil:
		log.SetOutput(io.MultiWriter(logfile, storeLogger))
	case storeLoggerError == nil:
		log.SetOutput(storeLogger)
	}

	collector, err := collection.NewCollector(store, tempDir, artifactDefinitions)
	if err != nil {
		logPrint(fmt.Errorf("LiveCollector creation failed: %w", err))
		return nil
	}

	i, total := 1, len(filteredArtifactDefinitions)

	// collect artifacts
	for _, artifactDefinition := range filteredArtifactDefinitions {
		startArtifact := time.Now()
		logPrint(fmt.Sprintf("Collecting %s (%d/%d)", artifactDefinition.Name, i, total))
		i++
		for _, source := range artifactDefinition.Sources {
			collector.Collect(artifactDefinition.Name, source)
		}
		log.Printf("Collected %s in %.1f seconds\n", artifactDefinition.Name, time.Since(startArtifact).Seconds())
	}

	log.Printf("Collected artifacts in %.1f seconds\n", time.Since(start).Seconds())

	// remove store logger
	if logfileError == nil {
		log.SetOutput(logfile)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	err = teardown()
	if err != nil {
		logPrint(fmt.Sprintf("Close Store failed: %s", err))
		return nil
	}

	logPrint("Collection done.")

	return &Collection{
		Name: collectionName,
		Path: storeName,
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

func addConfig(conn *sqlite.Conn, key string, value interface{}) error {
	stmt, err := conn.Prepare("INSERT INTO `config` (key, value) VALUES ($key, $value)")
	if err != nil {
		return err
	}

	b, err := json.Marshal(value)
	if err != nil {
		return err
	}

	stmt.SetText("$key", key)
	stmt.SetText("$value", string(b))

	_, err = stmt.Step()
	if err != nil {
		return err
	}

	return stmt.Finalize()
}

func logPrint(a ...interface{}) {
	log.Println(a...)
	fmt.Println(a...)
}
