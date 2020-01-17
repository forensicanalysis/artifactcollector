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

// Package artifactcollector provides a software that collects forensic artifacts
// on systems. These artifacts can be used in forensic investigations to understand
// attacker behavior on compromised computers.
//
// Features
//
// The artifactcollector offers the following features
//    - ️🖥️ Runs on 🖼️ Windows, 🐧 Linux and 🍏 macOS
//    - 🛍️ Can extract files, directories, registry entries, command and WMI output.
//    - ⭐ Uses the configurable and extensible [Forensics Artifacts](https://github.com/forensicanalysis/artifacts)
//    - 🤖 Can [be bundled](https://github.com/forensicanalysis/acpack) for automated execution
//    - 💾 Creates [structured output](https://github.com/forensicanalysis/forensicstore)
//    - ‍💻 Can run without admin/root rights
//    - 🕊️ It's open source
package main

import (
	"flag"
	"fmt"

	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/forensicanalysis/artifactcollector/assets"
	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore/goforensicstore"
	"github.com/forensicanalysis/fslib/filesystem/systemfs"
	"github.com/mholt/archiver"
	"github.com/pkg/errors"
)

//go:generate go get golang.org/x/tools/cmd/goimports github.com/cugu/go-resources/cmd/resources github.com/akavel/rsrc
//go:generate go run scripts/yaml2go/main.go pack/ac.yaml pack/artifacts/*
//go:generate resources -declare -var=FS -package assets -output assets/assets.go pack/bin/*
//go:generate rsrc -arch amd64 -manifest resources/artifactcollector.exe.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector.syso
//go:generate rsrc -arch 386 -manifest resources/artifactcollector32.exe.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector32.syso
//go:generate rsrc -arch amd64 -manifest resources/artifactcollector.exe.user.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector.user.syso
//go:generate rsrc -arch 386 -manifest resources/artifactcollector32.exe.user.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector32.user.syso

func main() {
	defer func() {
		if r := recover(); r != nil {
			logPrint("A critical error occurred: ", r)
		}
	}()

	// parse commandline
	config, err := parseCmdline()
	if err != nil {
		fmt.Println("Error parsing arguments: ", err)
		return
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
	logfile, logfileError := os.OpenFile(collectionName+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logfileError != nil {
		log.Printf("Could not open logfile %s\n", err)
	} else {
		log.SetOutput(logfile)
		defer logfile.Close()
	}

	// start running
	logPrint("Start to collect forensic artifacts. This might take a while.")
	notify(event{Type: beforeStart, Data: map[string]interface{}{}})

	// unpack internal files
	tempDir, err := unpack()
	if err != nil {
		logPrint(err)
		return
	}
	defer os.RemoveAll(tempDir) // clean up

	// enforce admin rights
	if err = enforceAdmin(!config.User); err != nil {
		logPrint(err)
		return
	}

	sourceFS, err := systemfs.New()
	if err != nil {
		logPrint(errors.Wrap(err, "system fs creation failed"))
		return
	}

	// create store
	storeName, store, err := createStore(collectionName, config)
	if err != nil {
		logPrint(err)
		return
	}

	// add store as log writer
	if logfileError == nil {
		log.SetOutput(io.MultiWriter(logfile, &storeLogger{store}))
	} else {
		log.SetOutput(io.MultiWriter(&storeLogger{store}))
	}

	collector := collection.Collector{SourceFS: sourceFS, Store: store, TempDir: tempDir}
	resolver := collection.NewResolver(assets.Artifacts, collector)

	// decode artifact definitions
	sourceChannel, sourceCount, err := goartifacts.ParallelProcessArtifacts(config.Artifacts, sourceFS, true, assets.Artifacts, resolver)
	if err != nil {
		logPrint(errors.Wrap(err, "Decode failed"))
		return
	}

	// collect artifacts
	collector.Collect(sourceChannel, sourceCount)

	err = store.Close()
	if err != nil {
		logPrint(errors.Wrap(err, "Close Store failed"))
		return
	}

	logPrint("Compress results.")
	time.Sleep(time.Millisecond * 500)

	// compress data
	if err := archiver.Archive([]string{storeName}, storeName+".zip"); err != nil {
		log.Printf("compression failed: %s", err)
	} else {
		err = os.RemoveAll(storeName)
		if err == nil {
			os.Rename(storeName+".zip", storeName) //nolint:errcheck
		} else {
			log.Printf("rename failed: %s", err)
		}
	}

	// Finalize running
	notify(event{Type: finished, Data: map[string]interface{}{
		"filename": storeName + ".zip",
		"case":     config.Case,
	}})
	logPrint("Collection done.")
	time.Sleep(time.Second)
}

func parseCmdline() (conf collection.Configuration, err error) {
	var unpackFlag bool
	// default configuration
	conf = *assets.Config
	conf.Type = "_config"

	// read from commandline
	flag.BoolVar(&unpackFlag, "unpack", unpackFlag, "unpack files")
	flag.BoolVar(&conf.User, "user", conf.User, "enable running without admin/root")
	flag.Parse()

	if unpackFlag {
		tempDir, err := unpack()
		fmt.Println(tempDir)
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if len(conf.Artifacts) == 0 {
		return conf, errors.New("No artifacts given")
	}
	return conf, nil
}

func unpack() (tempDir string, err error) {
	tempDir, err = ioutil.TempDir("", "ac")
	if err != nil {
		return tempDir, err
	}

	for path, content := range assets.FS.Files {
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

func createStore(collectionName string, c collection.Configuration) (string, *goforensicstore.ForensicStore, error) {
	storeName := fmt.Sprintf("%s.forensicstore", collectionName)
	store, err := goforensicstore.NewJSONLite(storeName)
	if err != nil {
		return "", nil, err
	}

	// insert configuration into store
	_, err = store.InsertStruct(c)
	if err != nil {
		log.Println(err)
	}

	// insert artifact definitions into store
	for _, artifact := range assets.Artifacts {
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
